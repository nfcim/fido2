import 'dart:async';

/// Session data stored on the server for a registration/login ceremony.
class SessionData {
  /// The challenge value as base64url string.
  final String challenge;

  /// The username associated with this session.
  final String username;

  /// Expiration time for this session data.
  final DateTime expires;

  SessionData({
    required this.challenge,
    required this.username,
    required this.expires,
  });
}

/// Abstraction for a session store.
/// Implementations can be in-memory, Redis, etc.
abstract class SessionStore {
  Future<void> save(String sessionId, SessionData data);
  Future<SessionData?> load(String sessionId);
  Future<void> delete(String sessionId);
  Future<void> clear();
}

/// Simple in-memory store for tests.
class InMemorySessionStore implements SessionStore {
  final Map<String, SessionData> _store = {};

  @override
  Future<void> save(String sessionId, SessionData data) async {
    _store[sessionId] = data;
  }

  @override
  Future<SessionData?> load(String sessionId) async {
    return _store[sessionId];
  }

  @override
  Future<void> delete(String sessionId) async {
    _store.remove(sessionId);
  }

  /// Testing helper to clear all sessions.
  @override
  Future<void> clear() async {
    _store.clear();
  }
}
