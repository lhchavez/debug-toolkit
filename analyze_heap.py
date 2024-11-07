import argparse
import copy
import gzip
import logging
import struct

RECORD_DONE = 0
RECORD_TYPE = 1
RECORD_OBJECT = 2
RECORD_OBJECT_WITH_PAYLOAD = 3


def _scanheap(filename: str) -> dict[int, tuple[int, str, int, str | None]]:
    typenames = {}
    live_objects: dict[int, tuple[int, str, int, str | None]] = {}
    if filename.endswith(".gz"):
        file = gzip.open(filename, "rb")
    else:
        file = open(filename, "rb")
    with file as f:
        while True:
            (record_kind,) = struct.unpack("B", f.read(1))
            if record_kind == RECORD_DONE:
                # !B
                logging.info("%s: %d live objects scanned", filename, len(live_objects))
                return live_objects
            elif record_kind == RECORD_TYPE:
                # !BQH{len(typename)}s
                objtype_addr, objtype_len = struct.unpack("!QH", f.read(10))
                typenames[objtype_addr] = f.read(objtype_len).decode("utf-8")
            elif record_kind == RECORD_OBJECT:
                # !BQQQL
                addr, parent_addr, objtype_addr, size = struct.unpack(
                    "!QQQL", f.read(28)
                )
                live_objects[addr] = (parent_addr, typenames[objtype_addr], size, None)
            elif record_kind == RECORD_OBJECT_WITH_PAYLOAD:
                # !BQQQLH{len(payload)}s
                addr, parent_addr, objtype_addr, size, payload_len = struct.unpack(
                    "!QQQLH", f.read(30)
                )
                payload = f.read(payload_len).decode("utf-8", "replace")
                live_objects[addr] = (
                    parent_addr,
                    typenames[objtype_addr],
                    size,
                    payload,
                )
            else:
                logging.fatal("unknown record kind %d", record_kind)
    logging.warning("incomplete file")
    return live_objects


def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--top-allocations",
        default=50,
        help="How many of the biggest allocations to show",
    )
    parser.add_argument(
        "--show-parents",
        action="store_true",
        help="Whether to show the parents of the biggest allocations",
    )
    parser.add_argument(
        "--previous-heap-dump",
        default=None,
        help="A previous heap dump. All live objects in the previous heap dump will be ignored.",
    )
    parser.add_argument("heap_dump")
    args = parser.parse_args()

    live_objects = _scanheap(args.heap_dump)
    all_objects = copy.copy(live_objects)

    if args.previous_heap_dump is not None:
        previous_objects = _scanheap(args.previous_heap_dump)
        # Keep all objects that have survived between the heap dumps.
        live_objects = {
            addr: all_objects[addr]
            for addr in (set(live_objects.keys()) & set(previous_objects.keys()))
        }

    for size, typename, addr, parent_addr, payload in sorted(
        (
            (size, typename, addr, parent_addr, payload)
            for addr, (parent_addr, typename, size, payload) in live_objects.items()
        ),
        reverse=True,
    )[: args.top_allocations]:
        logging.info(
            "%8d %016x %s %s",
            size,
            addr,
            typename,
            repr(payload) if payload is not None else "",
        )
        if args.show_parents:
            seen = set()
            while parent_addr != 0:
                if parent_addr in seen:
                    logging.info("loop")
                    break
                seen.add(parent_addr)
                addr = parent_addr
                parent_addr, typename, size, payload = all_objects[addr]
                logging.info(
                    "        %8d %016x %s %s",
                    size,
                    addr,
                    typename,
                    repr(payload) if payload is not None else "",
                )


if __name__ == "__main__":
    _main()
