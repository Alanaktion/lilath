package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session holds data associated with an authenticated user session.
type Session struct {
	Username  string
	ExpiresAt time.Time
}

// SessionStore is a thread-safe in-memory store for sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
}

// NewSessionStore creates a SessionStore with the given TTL and starts a
// background goroutine to prune expired sessions every minute.
func NewSessionStore(ttlMinutes int) *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      time.Duration(ttlMinutes) * time.Minute,
	}
	go s.cleanupLoop()
	return s
}

func (s *SessionStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.deleteExpired()
	}
}

func (s *SessionStore) deleteExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// Create creates a new session for username and returns the session ID.
func (s *SessionStore) Create(username string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sessions[id] = &Session{
		Username:  username,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	s.mu.Unlock()
	return id, nil
}

// Get retrieves a session by ID. Returns nil if the session does not exist or
// has expired.
func (s *SessionStore) Get(id string) *Session {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		s.Delete(id)
		return nil
	}
	return sess
}

// Refresh extends the session expiry by the store TTL.
func (s *SessionStore) Refresh(id string) {
	s.mu.Lock()
	if sess, ok := s.sessions[id]; ok {
		sess.ExpiresAt = time.Now().Add(s.ttl)
	}
	s.mu.Unlock()
}

// Delete removes a session.
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
