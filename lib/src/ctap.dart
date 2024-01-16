class CtapResponse<T> {
  final int status;
  final T data;

  CtapResponse(this.status, this.data);
}

abstract class CtapDevice {
  Future<CtapResponse<List<int>>> transceive(List<int> command);
}
