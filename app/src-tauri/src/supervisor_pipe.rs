// The second and only additional transport: service-owned elevated core.
#[cfg(windows)]
impl Supervisor {
    pub(crate) async fn service_pipe(
        pipe: tokio::net::windows::named_pipe::NamedPipeServer,
        process: crate::windows::identity::Handle,
        pid: u32,
        stamp: u64,
        lease: String,
    ) -> Result<Self> {
        let (mut input, mut output) = tokio::io::split(pipe);
        let (write, mut writes) = mpsc::channel::<Write>(MAX_INFLIGHT);
        let (control, mut controls) = mpsc::channel(1);
        let (life, _) = watch::channel(Life::Ready);
        let (exited, _) = watch::channel(false);
        let (exit, _) = watch::channel(None);
        let (close, mut closed) = watch::channel(false);
        let inner = Arc::new(Inner {
            stamp,
            checkpoint: Mutex::new(None),
            transport: "named_pipe",
            remote_owned: true,
            component_instance: AtomicU64::new(0),
            primary: AtomicU64::new(0),
            recent: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            log_permits: Arc::new(Semaphore::new(2)),
            probe_permits: Arc::new(Semaphore::new(MAX_INFLIGHT - 4)),
            next: AtomicU64::new(1),
            write,
            control,
            life,
            pid,
            exited,
            exit,
            update: AtomicBool::new(false),
            update_prepare_sent: AtomicBool::new(false),
            update_closing: AtomicBool::new(false),
            transport_closed: AtomicBool::new(false),
            unexpected_eof: AtomicBool::new(false),
            mutation: Mutex::new(None),
            mutation_hard_timeout_ms: AtomicU64::new(90_000),
            reconcile: tokio::sync::Mutex::new(()),
            _job: None,
        });
        let i = inner.clone();
        let closing = close.clone();
        tokio::spawn(async move {
            while let Some(message) = writes.recv().await {
                match message {
                    Write::Close => {
                        i.transport_closed.store(true, Ordering::Release);
                        let _ = output.shutdown().await;
                        closing.send_replace(true);
                        break;
                    }
                    Write::Frame(frame) => {
                        let result = async {
                            output.write_all(&frame).await?;
                            output.write_all(b"\n").await?;
                            output.flush().await
                        }
                        .await;
                        if let Err(e) = result {
                            i.fail(Error::io("CORE_WRITE", &e));
                            closing.send_replace(true);
                            break;
                        }
                    }
                }
            }
        });
        let i = inner.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(&mut input);
            loop {
                let result = tokio::select! {
                    r = crate::transport_diagnostics::read_frame(&mut reader) => r,
                    _ = closed.changed() => break
                };
                match result {
                    Ok(Some(frame)) => match Response::parse_observed(&frame) {
                        Ok(r) => {
                            i.observe_runtime_sample(&r, frame.len());
                            let tx = i.pending.lock().unwrap().remove(&r.id);
                            if let Some(tx) = tx {
                                let _ = tx.send(r.result());
                            } else {
                                i.observe_unmatched(&r.id, frame.len());
                            }
                        }
                        Err(e) => {
                            i.fail(e);
                            break;
                        }
                    },
                    Ok(None) => {
                        let expected_eof = i.transport_closed.load(Ordering::Acquire);
                        i.fail_with_expected_eof(
                            Error::new("CORE_EOF", "特权内核控制管道已关闭"),
                            expected_eof,
                        );
                        break;
                    }
                    Err(e) => {
                        i.fail(e);
                        break;
                    }
                }
            }
        });
        let i = inner.clone();
        tokio::spawn(async move {
            use windows_sys::Win32::{Foundation::*, System::Threading::*};
            let process = process;
            let cancel_event = Arc::new(crate::windows::identity::Handle(unsafe {
                CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
            }));
            if cancel_event.raw().is_null() {
                i.exit.send_replace(Some(ChildExit {
                    code: None,
                    forced: false,
                    wait_failed: true,
                }));
                i.fail(Error::new("CORE_EXIT_WAIT", "无法创建特权内核退出等待事件"));
                return;
            }
            // Duplicate process handle so the 0Hz blocking waiter owns an independent handle lifetime.
            let waiter_proc = {
                let mut waiter_raw = std::ptr::null_mut();
                let dup_ok = unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        process.raw(),
                        GetCurrentProcess(),
                        &mut waiter_raw,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS,
                    )
                } != 0;
                if !dup_ok {
                    i.exit.send_replace(Some(ChildExit {
                        code: None,
                        forced: false,
                        wait_failed: true,
                    }));
                    i.fail(Error::new("CORE_EXIT_WAIT", "无法复制特权内核句柄"));
                    return;
                }
                crate::windows::identity::Handle(waiter_raw)
            };
            let waiter_cancel = cancel_event.clone();
            let (wait_tx, mut wait_rx) = oneshot::channel::<u32>();
            std::thread::spawn(move || {
                let handles = [waiter_proc.raw(), waiter_cancel.raw()];
                let rc = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                let _ = wait_tx.send(rc);
            });

            let mut forced = false;
            let wait_rc = loop {
                tokio::select! {
                    rc = &mut wait_rx => break rc.unwrap_or(WAIT_FAILED),
                    command = controls.recv() => {
                        match command {
                            Some(()) => {
                                if !i.update.load(Ordering::Acquire) {
                                    let request = crate::service_protocol::ServiceRequest::Elevated {
                                        request: crate::elevated_protocol::ElevatedRequest::Shutdown {
                                            lease: lease.clone(),
                                            force: true,
                                        },
                                    };
                                    if let Ok(reply) = crate::windows::service_client::call(request).await {
                                        forced |= reply["forced"].as_bool().unwrap_or(true);
                                    }
                                }
                            }
                            None => {
                                unsafe { let _ = SetEvent(cancel_event.raw()); }
                                break wait_rx.await.unwrap_or(WAIT_FAILED);
                            }
                        }
                    }
                }
            };
            unsafe {
                let _ = SetEvent(cancel_event.raw());
            }
            if wait_rc == WAIT_OBJECT_0 || unsafe { WaitForSingleObject(process.raw(), 0) } == WAIT_OBJECT_0 {
                let mut code = 0;
                let ok = unsafe { GetExitCodeProcess(process.raw(), &mut code) } != 0;
                {
                    let i = i.clone();
                    let lease = lease.clone();
                    tokio::spawn(async move {
                        let reply = crate::windows::service_client::call(
                            crate::service_protocol::ServiceRequest::Elevated {
                                request: crate::elevated_protocol::ElevatedRequest::Status {
                                    lease: lease.clone(),
                                },
                            },
                        )
                        .await;
                        if let Ok(reply) = reply {
                            if let Ok(Some(summary)) = serde_json::from_value::<
                                Option<crate::crash_private::Summary>,
                            >(reply["private_stderr"].clone())
                            {
                                let category = if summary.present {
                                    "runtime_fatal"
                                } else {
                                    "discarded"
                                };
                                let mut d = crate::safe_log::RuntimeEvidence::new(
                                    "stderr",
                                    category,
                                    i.transport,
                                );
                                d.private_crash_present = Some(summary.present);
                                d.private_crash_truncated = Some(summary.truncated);
                                d.private_crash_write_failed = Some(summary.write_failed);
                                d.private_crash_bytes = Some(summary.saved_bytes);
                                d.private_crash_observed_bytes = Some(summary.observed_bytes);
                                let primary = i.primary.load(Ordering::Acquire);
                                crate::safe_log::runtime_event_at(
                                    i.component_instance.load(Ordering::Acquire),
                                    crate::log_context::Component::Core,
                                    "core.exit",
                                    (primary > 0).then_some(primary),
                                    d,
                                );
                            }
                        }
                    });
                }
                i.exit.send_replace(Some(ChildExit {
                    code: ok.then_some(code as i32),
                    forced,
                    wait_failed: !ok,
                }));
                i.exited.send_replace(true);
                i.fail(Error::new("CORE_EXITED", "特权内核进程已退出"));
                close.send_replace(true);
            } else if wait_rc != WAIT_OBJECT_0 + 1 {
                i.exit.send_replace(Some(ChildExit {
                    code: None,
                    forced,
                    wait_failed: true,
                }));
                i.fail(Error::new("CORE_EXIT_WAIT", "无法确认特权内核退出状态"));
            }
        });
        Ok(Self(inner))
    }
    pub(crate) fn service_owned(&self) -> bool {
        self.0.remote_owned
    }
}
