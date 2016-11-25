extern crate kqueue_sys;
extern crate libc;

use kqueue_sys::{kqueue, kevent};
use libc::{pid_t, uintptr_t};
use std::collections::HashMap;
use std::convert::AsRef;
use std::fs::File;
use std::io::{self, Error, Result};
use std::path::Path;
use std::ptr;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

pub use kqueue_sys::constants::*;

#[derive(Debug, PartialEq, Clone)]
pub struct Watched {
    filter: EventFilter,
    flags: FilterFlag,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum Ident {
    Filename(RawFd, String),
    Fd(RawFd),
    Pid(pid_t),
    Signal(i32),
    Timer(i32),
}

#[derive(Debug)]
pub struct Watcher {
    watched: HashMap<Ident, Watched>,
    queue: RawFd,
    started: bool,
}

#[derive(Debug)]
pub enum Vnode {
    Delete,
    Write,
    Extend,
    Truncate,
    Attrib,
    Link,
    Rename,
    Revoke,
}

#[derive(Debug)]
pub enum Proc {
    Exit(usize),
    Fork,
    Exec,
    Track(libc::pid_t),
    Trackerr,
}

// These need to be OS specific
#[derive(Debug)]
pub enum EventData {
    Vnode(Vnode),
    Proc(Proc),
    ReadReady(usize),
    WriteReady(usize),
    Signal(usize),
    Timer(usize),
    Error(Error),
}

#[derive(Debug)]
pub struct Event {
    pub ident: Ident,
    pub data: EventData,
}

pub struct EventIter<'a> {
    watcher: &'a Watcher,
}

impl Watcher {
    pub fn new() -> Result<Watcher> {
        let queue = unsafe { kqueue() };

        if queue == -1 {
            Err(Error::last_os_error())
        } else {
            Ok(Watcher {
                watched: HashMap::new(),
                queue: queue,
                started: false,
            })
        }
    }

    pub fn add_filename<P: AsRef<Path>>(&mut self,
                                        filename: P,
                                        filter: EventFilter,
                                        flags: FilterFlag)
                                        -> Result<()> {
        let file = try!(File::open(filename.as_ref()));
        self.watched.insert(Ident::Filename(file.into_raw_fd(),
                                            filename.as_ref().to_string_lossy().into_owned()),
                            Watched {
                                filter: filter,
                                flags: flags,
                            });
        Ok(())
    }

    pub fn add_fd(&mut self, fd: RawFd, filter: EventFilter, flags: FilterFlag) -> Result<()> {
        self.watched.insert(Ident::Fd(fd),
                            Watched {
                                filter: filter,
                                flags: flags,
                            });
        Ok(())
    }

    pub fn add_file(&mut self, file: File, filter: EventFilter, flags: FilterFlag) -> Result<()> {
        self.add_fd(file.into_raw_fd(), filter, flags)
    }

    pub fn watch(&mut self) -> Result<()> {
        let mut kevs: Vec<kevent> = Vec::new();

        for (ident, watched) in &self.watched {
            let raw_ident = match *ident {
                Ident::Fd(fd) => fd as uintptr_t,
                Ident::Filename(fd, _) => fd as uintptr_t,
                Ident::Pid(pid) => pid as uintptr_t,
                Ident::Signal(sig) => sig as uintptr_t,
                Ident::Timer(ident) => ident as uintptr_t,
            };

            kevs.push(kevent {
                ident: raw_ident,
                filter: watched.filter,
                flags: EV_ADD,
                fflags: watched.flags,
                data: 0,
                udata: ptr::null_mut(),
            });
        }

        let ret = unsafe {
            kevent(self.queue,
                   kevs.as_ptr(),
                   kevs.len() as i32,
                   ptr::null_mut(),
                   0,
                   ptr::null())
        };

        self.started = true;
        match ret {
            -1 => Err(Error::last_os_error()),
            _ => Ok(()),
        }
    }

    pub fn iter(&self) -> EventIter {
        EventIter { watcher: self }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        unsafe { libc::close(self.queue) };
        for (ident, _) in &self.watched {
            match *ident {
                Ident::Fd(fd) => unsafe { libc::close(fd) },
                Ident::Filename(fd, _) => unsafe { libc::close(fd) },
                _ => continue,
            };
        }
    }
}

#[inline]
fn find_file_ident(watcher: &Watcher, fd: RawFd) -> Option<Ident> {
    for (ident, _) in &watcher.watched {
        match ident.clone() {
            Ident::Fd(ident_fd) => {
                if fd == ident_fd {
                    return Some(Ident::Fd(fd));
                } else {
                    continue;
                }
            }
            Ident::Filename(ident_fd, ident_str) => {
                if fd == ident_fd {
                    return Some(Ident::Filename(ident_fd, ident_str));
                } else {
                    continue;
                }
            }
            _ => continue,
        }
    }

    None
}

// OS specific
impl Event {
    pub fn new(ev: kevent, watcher: &Watcher) -> Event {
        let data = match ev.filter {
            EventFilter::EVFILT_READ => EventData::ReadReady(ev.data as usize),
            EventFilter::EVFILT_WRITE => EventData::WriteReady(ev.data as usize),
            EventFilter::EVFILT_SIGNAL => EventData::Signal(ev.data as usize),
            EventFilter::EVFILT_TIMER => EventData::Timer(ev.data as usize),
            EventFilter::EVFILT_PROC => {
                let inner = if ev.fflags.contains(NOTE_EXIT) {
                    Proc::Exit(ev.data as usize)
                } else if ev.fflags.contains(NOTE_FORK) {
                    Proc::Fork
                } else if ev.fflags.contains(NOTE_EXEC) {
                    Proc::Exec
                } else if ev.fflags.contains(NOTE_TRACK) {
                    Proc::Track(ev.data as libc::pid_t)
                } else {
                    panic!("not supported")
                };

                EventData::Proc(inner)
            }
            EventFilter::EVFILT_VNODE => {
                let inner = if ev.fflags.contains(NOTE_DELETE) {
                    Vnode::Delete
                } else if ev.fflags.contains(NOTE_WRITE) {
                    Vnode::Write
                } else if ev.fflags.contains(NOTE_EXTEND) {
                    Vnode::Extend
                } else if ev.fflags.contains(NOTE_ATTRIB) {
                    Vnode::Attrib
                } else if ev.fflags.contains(NOTE_LINK) {
                    Vnode::Link
                } else if ev.fflags.contains(NOTE_RENAME) {
                    Vnode::Rename
                } else if ev.fflags.contains(NOTE_REVOKE) {
                    Vnode::Revoke
                } else {
                    panic!("not supported")
                };

                EventData::Vnode(inner)
            }
            _ => panic!("not supported"),
        };

        let ident = match ev.filter {
            EventFilter::EVFILT_READ => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_WRITE => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_VNODE => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_SIGNAL => Ident::Signal(ev.ident as i32),
            EventFilter::EVFILT_TIMER => Ident::Timer(ev.ident as i32),
            EventFilter::EVFILT_PROC => Ident::Pid(ev.ident as pid_t),
            _ => panic!("not supported"),
        };

        Event {
            ident: ident,
            data: data,
        }
    }

    pub fn from_error(ev: kevent, watcher: &Watcher) -> Event {
        let ident = match ev.filter {
            EventFilter::EVFILT_READ => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_WRITE => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_VNODE => find_file_ident(watcher, ev.ident as RawFd).unwrap(),
            EventFilter::EVFILT_SIGNAL => Ident::Signal(ev.ident as i32),
            EventFilter::EVFILT_TIMER => Ident::Timer(ev.ident as i32),
            EventFilter::EVFILT_PROC => Ident::Pid(ev.ident as pid_t),
            _ => panic!("not supported"),
        };

        Event {
            data: EventData::Error(io::Error::last_os_error()),
            ident: ident,
        }
    }

    #[inline]
    pub fn is_err(&self) -> bool {
        match self.data {
            EventData::Error(_) => true,
            _ => false,
        }
    }
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Event;

    // rather than call kevent(2) each time, we can likely optimize and
    // call it once for like 100 items
    fn next(&mut self) -> Option<Self::Item> {
        if !self.watcher.started {
            return None;
        }

        let queue = self.watcher.queue;
        let mut kev = kevent {
            ident: 0,
            data: 0,
            filter: EventFilter::EVFILTER_SYSCOUNT,
            fflags: FilterFlag::empty(),
            flags: EventFlag::empty(),
            udata: ptr::null_mut(),
        };

        let ret = unsafe { kevent(queue, ptr::null(), 0, &mut kev, 1, ptr::null()) };

        match ret {
            -1 => Some(Event::from_error(kev, self.watcher)),
            0 => None,  // timeout expired
            _ => Some(Event::new(kev, self.watcher)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use super::{Watcher, EventFilter, EventData, NOTE_WRITE, Vnode, Ident};

    #[test]
    fn test_new_watcher() {
        let mut watcher = Watcher::new().unwrap();
        let file = fs::File::create("testing.txt").unwrap();

        assert!(watcher.add_file(file, EventFilter::EVFILT_VNODE, NOTE_WRITE).is_ok(),
                "add failed");
        assert!(watcher.watch().is_ok(), "watch failed");
    }

    #[test]
    fn test_filename() {
        let filename = "/tmp/testing.txt";
        let mut watcher = match Watcher::new() {
            Ok(wat) => wat,
            Err(_) => panic!("new failed"),
        };

        {
            assert!(fs::File::create(filename).is_ok(), "file creation failed");
        };

        assert!(watcher.add_filename(filename, EventFilter::EVFILT_VNODE, NOTE_WRITE).is_ok(),
                "add failed");
        assert!(watcher.watch().is_ok(), "watch failed");

        let mut new_file = match fs::OpenOptions::new().write(true).open(filename) {
            Ok(fil) => fil,
            Err(_) => panic!("open failed"),
        };

        assert!(new_file.write_all(b"foo").is_ok(), "write failed");
        let ev = watcher.iter().next().unwrap();
        match ev.data {
            EventData::Vnode(Vnode::Write) => assert!(true),
            _ => assert!(false),
        };

        match ev.ident {
            Ident::Filename(_, name) => assert!(name == filename),
            _ => assert!(false),
        };
    }

    #[test]
    fn test_file() {
        let filename = "/tmp/testing.txt";
        let mut watcher = match Watcher::new() {
            Ok(wat) => wat,
            Err(_) => panic!("new failed"),
        };

        let file_res = fs::File::create(filename);
        assert!(file_res.is_ok(), "file creation failed");
        let file = file_res.unwrap();

        assert!(watcher.add_file(file, EventFilter::EVFILT_VNODE, NOTE_WRITE).is_ok(),
                "add failed");
        assert!(watcher.watch().is_ok(), "watch failed");

        let mut new_file = match fs::OpenOptions::new().write(true).open(filename) {
            Ok(fil) => fil,
            Err(_) => panic!("open failed"),
        };

        assert!(new_file.write_all(b"foo").is_ok(), "write failed");
        let ev = watcher.iter().next().unwrap();
        match ev.data {
            EventData::Vnode(Vnode::Write) => assert!(true),
            _ => assert!(false),
        };

        match ev.ident {
            Ident::Fd(_) => assert!(true),
            _ => assert!(false),
        };
    }
}
