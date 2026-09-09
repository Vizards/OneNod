package main

import "time"

const maximumAdmissionWait = time.Second

// Bound both waiters and elapsed wait. The same decision start time is passed
// to the authoritative provider call, so queueing cannot extend its deadline.
func (service *gatekeeperService) acquireDecisionSlot(started time.Time) bool {
	if !started.Add(time.Duration(service.config.Invocation.TimeoutMS) * time.Millisecond).After(time.Now()) {
		return false
	}
	select {
	case service.semaphore <- struct{}{}:
		return true
	default:
	}
	select {
	case service.waitingSlots <- struct{}{}:
		defer func() { <-service.waitingSlots }()
	default:
		return false
	}
	wait := time.Until(started.Add(time.Duration(service.config.Invocation.TimeoutMS) * time.Millisecond))
	if wait > maximumAdmissionWait {
		wait = maximumAdmissionWait
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case service.semaphore <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}
