List<int> hexStringToList(String hex) {
  List<int> result = [];

  // Remove leading '0x' if present
  if (hex.startsWith('0x')) {
    hex = hex.substring(2);
  }

  // Pad the string with a leading zero if it's not even in length
  if (hex.length % 2 != 0) {
    hex = '0$hex';
  }

  // Iterate over the string in steps of 2 characters
  for (int i = 0; i < hex.length; i += 2) {
    // Get a substring of two characters and convert it to an integer
    String byteString = hex.substring(i, i + 2);
    int byteInt = int.parse(byteString, radix: 16);
    result.add(byteInt);
  }

  return result;
}
