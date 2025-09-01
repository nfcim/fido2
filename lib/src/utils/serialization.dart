import 'dart:convert';

mixin JsonToStringMixin {
  Map<String, dynamic> toJson();
  @override
  String toString() => jsonEncode(toJson());
}
