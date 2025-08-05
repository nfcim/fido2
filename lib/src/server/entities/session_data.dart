/// Data decoded from a verified stateless session token.
class StatelessSessionData {
  final String challenge; // Stored as base64url
  final String username;
  final DateTime expires;

  StatelessSessionData({
    required this.challenge,
    required this.username,
    required this.expires,
  });

  factory StatelessSessionData.fromJson(Map<String, dynamic> json) {
    return StatelessSessionData(
      challenge: json['challenge'],
      username: json['username'],
      expires: DateTime.parse(json['expires']),
    );
  }
}
