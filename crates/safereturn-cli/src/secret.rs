use std::io::{self, Write};

trait Console {
    fn mode(&self) -> io::Result<u32>;
    fn set_mode(&self, mode: u32) -> io::Result<()>;
    fn read_line(&self, line: &mut String) -> io::Result<usize>;
}

struct EchoGuard<'a, C: Console> {
    console: &'a C,
    original: u32,
    restored: bool,
}

impl<C: Console> EchoGuard<'_, C> {
    fn restore(&mut self) -> io::Result<()> {
        self.console.set_mode(self.original)?;
        self.restored = true;
        Ok(())
    }
}

impl<C: Console> Drop for EchoGuard<'_, C> {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.console.set_mode(self.original);
        }
    }
}

fn read_secret(console: &impl Console, prompt: &str, out: &mut impl Write) -> io::Result<String> {
    let original = console.mode()?;
    let mut guard = EchoGuard {
        console,
        original,
        restored: false,
    };
    console.set_mode(original & !4)?; // ENABLE_ECHO_INPUT
    let read = (|| {
        write!(out, "{prompt}")?;
        out.flush()?;
        let mut line = String::new();
        if console.read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_owned())
    })();
    guard.restore()?;
    writeln!(out)?;
    read
}

pub(super) fn prompt(prompt: &str) -> Option<String> {
    #[cfg(windows)]
    {
        read_secret(&native::Input::open()?, prompt, &mut io::stderr()).ok()
    }
    #[cfg(not(windows))]
    {
        let _ = prompt;
        None
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }

    pub(super) struct Input(*mut c_void);
    impl Input {
        pub(super) fn open() -> Option<Self> {
            // SAFETY: STD_INPUT_HANDLE is a documented constant; this borrows the handle.
            let handle = unsafe { GetStdHandle(-10i32 as u32) };
            if handle.is_null() || handle as isize == -1 {
                None
            } else {
                Some(Self(handle))
            }
        }
    }
    impl Console for Input {
        fn mode(&self) -> io::Result<u32> {
            let mut mode = 0;
            // SAFETY: the borrowed input handle and writable mode pointer are valid.
            if unsafe { GetConsoleMode(self.0, &mut mode) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(mode)
            }
        }
        fn set_mode(&self, mode: u32) -> io::Result<()> {
            // SAFETY: the handle is borrowed; mode derives from GetConsoleMode.
            if unsafe { SetConsoleMode(self.0, mode) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        fn read_line(&self, line: &mut String) -> io::Result<usize> {
            io::stdin().read_line(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Mock {
        modes: RefCell<Vec<u32>>,
        fail: &'static str,
    }
    impl Console for Mock {
        fn mode(&self) -> io::Result<u32> {
            if self.fail == "mode" {
                Err(io::ErrorKind::Other.into())
            } else {
                Ok(7)
            }
        }
        fn set_mode(&self, mode: u32) -> io::Result<()> {
            self.modes.borrow_mut().push(mode);
            if self.fail == "disable" && mode == 3 || self.fail == "restore" && mode == 7 {
                Err(io::ErrorKind::Other.into())
            } else {
                Ok(())
            }
        }
        fn read_line(&self, line: &mut String) -> io::Result<usize> {
            match self.fail {
                "read" => Err(io::ErrorKind::Other.into()),
                "eof" => Ok(0),
                "panic" => panic!("injected read panic"),
                _ => {
                    line.push_str("private-secret\r\n");
                    Ok(line.len())
                }
            }
        }
    }

    #[test]
    fn output_failure_restores_before_returning() {
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let mock = Mock {
            modes: RefCell::new(Vec::new()),
            fail: "",
        };
        assert!(read_secret(&mock, "Password: ", &mut BrokenOutput).is_err());
        assert_eq!(*mock.modes.borrow(), [3, 7]);
    }

    #[test]
    fn restores_exact_mode_on_all_exits_without_printing_secret() {
        for fail in ["", "mode", "disable", "restore", "read", "eof", "panic"] {
            let mock = Mock {
                modes: RefCell::new(Vec::new()),
                fail,
            };
            let mut output = Vec::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                read_secret(&mock, "Password: ", &mut output)
            }));
            assert!(!String::from_utf8(output)
                .unwrap()
                .contains("private-secret"));
            if fail == "mode" {
                assert!(mock.modes.borrow().is_empty());
            } else {
                assert_eq!(mock.modes.borrow()[..2], [3, 7]);
            }
            match result {
                Ok(Ok(secret)) => {
                    assert_eq!(fail, "");
                    assert_eq!(secret, "private-secret");
                }
                Ok(Err(_)) => assert!(!fail.is_empty()),
                Err(_) => assert_eq!(fail, "panic"),
            }
        }
    }
}
