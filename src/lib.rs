extern crate kqueue_sys;
extern crate libc;

use kqueue_sys::{kqueue, kevent};
use libc::{pid_t, uintptr_t};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, Result};
use std::ptr;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

pub use kqueue_sys::constants::*;

#[derive(Debug)]
struct Watched {
    filter: EventFilter,
    flags: FilterFlag,
}

#[derive(Debug)]
struct WatchedFile {
    fd: RawFd,
    filter: EventFilter,
    flags: FilterFlag,
}

#[derive(Debug)]
pub struct Watcher {
    watched_files: HashMap<String, WatchedFile>,
    watched_fds: HashMap<RawFd, Watched>,
    watched_pids: HashMap<pid_t, Watched>,
    queue: RawFd,
    started: bool,
}

#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub enum Proc {
    Exit(usize),
    Fork,
    Exec,
    Track(libc::pid_t),
    Trackerr,
}

// These need to be OS specific
#[derive(Debug, PartialEq)]
pub enum EventData {
    Vnode(Vnode),
    Proc(Proc),
    ReadReady(usize),
    WriteReady(usize),
    Signal(usize),
    Timer(usize),
}

pub struct Event {
    pub ident: u32,  // TODO: change this to include the identity that we passed to add_*
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
                watched_files: HashMap::new(),
                watched_fds: HashMap::new(),
                watched_pids: HashMap::new(),
                queue: queue,
                started: false,
            })
        }
    }

    pub fn add_filename(&mut self,
                        filename: &str,
                        filter: EventFilter,
                        flags: FilterFlag)
                        -> Result<()> {
        let file = try!(File::open(filename));
        self.watched_files.insert(filename.to_string(),
                                  WatchedFile {
                                      filter: filter,
                                      flags: flags,
                                      fd: file.into_raw_fd(),
                                  });
        Ok(())
    }

    pub fn add_file(&mut self, file: File, filter: EventFilter, flags: FilterFlag) -> Result<()> {
        self.watched_fds.insert(file.into_raw_fd(),
                                Watched {
                                    filter: filter,
                                    flags: flags,
                                });
        Ok(())
    }

    pub fn watch(&mut self) -> Result<()> {
        let mut kevs: Vec<kevent> = Vec::new();

        for (fd, watched) in &self.watched_fds {
            kevs.push(kevent {
                ident: *fd as uintptr_t,
                filter: watched.filter,
                flags: EV_ADD,
                fflags: watched.flags,
                data: 0,
                udata: ptr::null_mut(),
            });
        }

        for (_, watched) in &self.watched_files {
            kevs.push(kevent {
                ident: watched.fd as uintptr_t,
                filter: watched.filter,
                flags: EV_ADD,
                fflags: watched.flags,
                data: 0,
                udata: ptr::null_mut(),
            });
        }

        for (pid, watched) in &self.watched_pids {
            kevs.push(kevent {
                ident: *pid as uintptr_t,
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
        for (fd, _) in &self.watched_fds {
            unsafe { libc::close(*fd) };
        }

        for (_, watched_data) in &self.watched_files {
            unsafe { libc::close(watched_data.fd) };
        }
    }
}

// OS specific
impl Event {
    pub fn new(ev: kevent) -> Event {
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

        Event {
            ident: ev.ident as u32,
            data: data,
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
            filter: EventFilter::EVFILT_SYSCOUNT,
            fflags: FilterFlag::empty(),
            flags: EventFlag::empty(),
            udata: ptr::null_mut(),
        };

        let ret = unsafe { kevent(queue, ptr::null(), 0, &mut kev, 1, ptr::null()) };

        match ret {
            -1 => None, // other error
            0 => None,  // timeout expired
            _ => Some(Event::new(kev)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use super::{Watcher, EventFilter, EventData, NOTE_WRITE, Vnode};

    #[test]
    fn test_new_watcher() {
        let mut watcher = Watcher::new().unwrap();
        let file = fs::File::create("testing.txt").unwrap();

        assert!(watcher.add_file(file, EventFilter::EVFILT_VNODE, NOTE_WRITE).is_ok(),
                "add failed");
        assert!(watcher.watch(), "watch failed");
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
    }
}
