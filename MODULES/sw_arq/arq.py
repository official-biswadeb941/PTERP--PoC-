from collections import deque
from typing import Dict, List, Optional, Set, Deque


class Packet:
    def __init__(self, seq_num: int, data: bytes) -> None:
        self.seq_num: int = seq_num
        self.data: bytes = data


def seq_in_range(start: int, seq: int, end: int, max_seq: int) -> bool:
    """Check if seq is in the window [start, end) under modulo max_seq."""
    if start <= end:
        return start <= seq < end
    else:
        return seq >= start or seq < end


class Sender:
    def __init__(self, window_size: int, max_seq: int) -> None:
        self.window_size: int = window_size
        self.max_seq: int = max_seq
        self.base: int = 0
        self.next_seq: int = 0
        self.window: Dict[int, Packet] = {}
        self.acked: Set[int] = set()

    def has_data_to_send(self) -> bool:
        return (self.next_seq - self.base) % self.max_seq < self.window_size

    def enqueue_data(self, data_chunk: bytes) -> Optional[Packet]:
        if self.has_data_to_send():
            seq_num = self.next_seq % self.max_seq
            pkt = Packet(seq_num, data_chunk)
            self.window[seq_num] = pkt
            self.next_seq = (self.next_seq + 1) % self.max_seq
            return pkt
        return None

    def mark_ack(self, ack_seq: int) -> None:
        if ack_seq in self.window:
            self.acked.add(ack_seq)
            while self.base % self.max_seq in self.acked:
                del self.window[self.base % self.max_seq]
                self.acked.remove(self.base % self.max_seq)
                self.base = (self.base + 1) % self.max_seq

    def get_unacked_packets(self) -> List[Packet]:
        return list(self.window.values())

    def is_done(self) -> bool:
        return self.base == self.next_seq and not self.window


class Receiver:
    def __init__(self, window_size: int, max_seq: int) -> None:
        self.window_size: int = window_size
        self.max_seq: int = max_seq
        self.expected: int = 0
        self.buffer: Dict[int, Packet] = {}
        self.output: Deque[bytes] = deque()

    def receive_packet(self, pkt: Packet) -> None:
        seq = pkt.seq_num
        window_end = (self.expected + self.window_size) % self.max_seq
        if seq_in_range(self.expected, seq, window_end, self.max_seq):
            if seq not in self.buffer:
                self.buffer[seq] = pkt
            self._deliver_in_order()

    def _deliver_in_order(self) -> None:
        while self.expected in self.buffer:
            self.output.append(self.buffer[self.expected].data)
            del self.buffer[self.expected]
            self.expected = (self.expected + 1) % self.max_seq

    def get_delivered_data(self) -> List[bytes]:
        result = list(self.output)
        self.output.clear()
        return result

    def get_ack_for(self, pkt: Packet) -> int:
        return pkt.seq_num
