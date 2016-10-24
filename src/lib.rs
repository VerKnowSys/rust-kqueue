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

        match ret {
            -1 => Err(Error::last_os_error()),
            _ => Ok(()),
        }
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

#[cfg(test)]
mod tests {
    use std::fs;
    use super::{EventFilter, NOTE_WRITE, Watcher};

    #[test]
    fn test_new_watcher() {
        let mut watcher = Watcher::new().unwrap();
        let file = fs::File::create("testing.txt").unwrap();
        watcher.add_file(file, EventFilter::EVFILT_VNODE, NOTE_WRITE);
        watcher.watch();
    }
}
