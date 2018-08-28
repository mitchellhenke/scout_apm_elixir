defmodule TcpServer do
  use GenServer

  def start_link() do
    ip = Application.get_env(:tcp_server, :ip, {127, 0, 0, 1})
    port = Application.get_env(:tcp_server, :port, 9000)
    GenServer.start_link(__MODULE__, [ip, port], [])
  end

  def init([ip, port]) do
    {:ok, socket} = :gen_tcp.connect(ip, port, [{:active, false}, :binary])
    {:ok, %{ip: ip, port: port, socket: socket}}
  end

  def handle_cast({:send, message}, %{socket: socket} = state) when is_map(message) do
    with {:ok, encoded} <- Poison.encode(message),
         message_length <- byte_size(encoded),
         binary_length <- pad_leading(:binary.encode_unsigned(message_length, :big), 4, 0),
         :ok <- :gen_tcp.send(socket, binary_length),
         :ok <- :gen_tcp.send(socket, encoded),
         {:ok, <<message_length::big-unsigned-integer-size(32)>>} <- :gen_tcp.recv(socket, 4),
         {:ok, msg} <- :gen_tcp.recv(socket, message_length),
         {:ok, decoded_msg} <- Poison.decode(msg) do
      IO.inspect(message_length, label: "MESSAGE LENGTH")
      IO.inspect(decoded_msg, label: "MESSAGE")
    end

    {:noreply, state}
  end

  def handle_info({:tcp, socket, packet}, state) do
    IO.inspect(packet, label: "incoming packet")
    {:noreply, state}
  end

  def handle_info({:tcp_closed, _socket}, state) do
    IO.inspect("Socket has been closed")
    {:noreply, state}
  end

  def handle_info({:tcp_error, socket, reason}, state) do
    IO.inspect(socket, label: "connection closed dut to #{reason}")
    {:noreply, state}
  end

  def pad_leading(binary, len, byte \\ 0)

  def pad_leading(binary, len, byte)
      when is_binary(binary) and is_integer(len) and is_integer(byte) and len > 0 and
             byte_size(binary) >= len,
      do: binary

  def pad_leading(binary, len, byte)
      when is_binary(binary) and is_integer(len) and is_integer(byte) and len > 0 do
    (<<byte>> |> :binary.copy(len - byte_size(binary))) <> binary
  end
end
