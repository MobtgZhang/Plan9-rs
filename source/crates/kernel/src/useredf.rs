use crate::dev::Error;
use crate::proc::{Proc, State};

const DENSITY_SCALE: u64 = 1_000_000;

#[derive(Default)]
pub(crate) struct Reservation {
    period: u64,
    deadline: u64,
    cost: u64,
    sporadic: bool,
    extra: bool,
    deadline_notes: bool,
    job: Option<Job>,
}

struct Job {
    deadline: u64,
    next_release: u64,
    budget: u64,
    yielded: bool,
    running_since: Option<u64>,
}

impl Reservation {
    fn relative_deadline(&self) -> u64 {
        if self.deadline == 0 { self.period } else { self.deadline }
    }

    fn density(&self) -> u64 {
        (self.cost * DENSITY_SCALE).div_ceil(self.relative_deadline())
    }

    pub(crate) fn admitted(&self) -> bool {
        self.job.is_some()
    }

    fn release(&self, now: u64, next_release: u64) -> Job {
        Job {
            deadline: now.saturating_add(self.relative_deadline()),
            next_release,
            budget: self.cost,
            yielded: false,
            running_since: None,
        }
    }

    fn refresh(&mut self, now: u64, runnable: bool) -> bool {
        let Some(job) = &mut self.job else { return false };
        let missed = now >= job.deadline && job.budget != 0 && !job.yielded;
        if now >= job.deadline {
            job.budget = 0;
        }
        if runnable && now >= job.next_release {
            let next = if self.sporadic {
                now.saturating_add(self.period)
            } else {
                now.saturating_add(self.period - (now - job.next_release) % self.period)
            };
            self.job = Some(self.release(now, next));
        }
        missed && runnable && self.deadline_notes
    }
}

fn duration_ms(value: &str) -> Result<u64, Error> {
    let (number, scale) = [("ms", 1_000_000), ("us", 1_000), ("µs", 1_000), ("ns", 1), ("s", 1_000_000_000)]
        .into_iter().find_map(|(suffix, scale)| value.strip_suffix(suffix).map(|number| (number, scale)))
        .unwrap_or((value, 1_000_000_000));
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !(digits(whole) || whole.is_empty() && digits(fraction))
        || (number.contains('.') && (!digits(fraction) || fraction.len() > 9))
    {
        return Err(Error::Einval);
    }
    let whole = if whole.is_empty() { 0 } else { whole.parse::<u64>().map_err(|_| Error::Einval)? };
    let fraction_ns = fraction.parse::<u64>().unwrap_or(0) * scale / 10u64.pow(fraction.len() as u32);
    let ns = whole.checked_mul(scale).and_then(|ns| ns.checked_add(fraction_ns)).ok_or(Error::Einval)?;
    let tick = crate::timer::MS_PER_TICK * 1_000_000;
    if ns % tick != 0 || ns / 1_000_000 > u32::MAX as u64 {
        return Err(Error::Einval);
    }
    Ok(ns / 1_000_000)
}

pub(crate) fn configure(proc: &mut Proc, command: &str, argument: Option<&str>) -> Result<(), Error> {
    if proc.state == State::Broken {
        return Err(Error::Einval);
    }
    if command == "expel" {
        if let Some(edf) = &mut proc.user_edf {
            edf.job = None;
        }
        return Ok(());
    }
    let edf = proc.user_edf.get_or_insert_with(Reservation::default);
    match command {
        "period" | "deadline" | "cost" => {
            let duration = duration_ms(argument.ok_or(Error::Einval)?)?;
            edf.job = None;
            match command {
                "period" => edf.period = duration,
                "deadline" => edf.deadline = duration,
                _ => edf.cost = duration,
            }
        }
        "sporadic" => edf.sporadic = true,
        "extra" => edf.extra = true,
        "deadlinenotes" => edf.deadline_notes = true,
        "admit" => {
            let deadline = edf.relative_deadline();
            if edf.admitted() || edf.cost == 0 || edf.cost > deadline || deadline > edf.period {
                return Err(Error::Einval);
            }
            let density = crate::proc::proctable().iter().filter(|other| other.pid != proc.pid)
                .filter_map(|other| other.user_edf.as_ref().filter(|edf| edf.admitted()))
                .fold(edf.density(), |total, other| total.saturating_add(other.density()));
            if density > DENSITY_SCALE {
                return Err(Error::Einval);
            }
            let now = plan9_arch::hal::timer::ms_since_boot();
            let mut job = edf.release(now, now.saturating_add(edf.period));
            if proc.state == State::Running {
                job.running_since = Some(now);
            } else if proc.state != State::Ready {
                job.next_release = now;
                job.budget = 0;
            }
            edf.job = Some(job);
        }
        _ => return Err(Error::Einval),
    }
    Ok(())
}

pub(crate) fn update(proc: &mut Proc, now: u64) {
    if proc.user_edf.as_mut().is_some_and(|edf| edf.refresh(now, matches!(proc.state, State::Ready | State::Running))) {
        let _ = proc.postnote(0, b"deadline missed");
    }
}

pub(crate) fn dispatch(proc: &mut Proc, now: u64) {
    if let Some(job) = proc.user_edf.as_mut().and_then(|edf| edf.job.as_mut()) {
        job.running_since = Some(now);
    }
}

pub(crate) fn account(proc: &mut Proc, now: u64) {
    if let Some(job) = proc.user_edf.as_mut().and_then(|edf| edf.job.as_mut()) {
        if let Some(start) = job.running_since.take() {
            job.budget = job.budget.saturating_sub(job.deadline.min(now).saturating_sub(start));
        }
    }
    update(proc, now);
}

pub(crate) fn yield_job(proc: &mut Proc) -> bool {
    if let Some(job) = proc.user_edf.as_mut().and_then(|edf| edf.job.as_mut()) {
        job.yielded = true;
        true
    } else {
        false
    }
}

pub(crate) fn rank(proc: &Proc) -> Option<(u8, u64)> {
    if let Some((edf, job)) = proc.user_edf.as_ref().and_then(|edf| edf.job.as_ref().map(|job| (edf, job))) {
        if job.yielded {
            return None;
        }
        if job.budget != 0 {
            return Some((0, job.deadline));
        }
        return edf.extra.then_some((2, 0));
    }
    Some((1, u64::from(i8::MAX.abs_diff(proc.pri))))
}
