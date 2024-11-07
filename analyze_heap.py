import argparse
import copy
import gzip
import logging
import struct
from typing import NamedTuple

RECORD_DONE = 0
RECORD_TYPE = 1
RECORD_OBJECT = 2
RECORD_OBJECT_WITH_PAYLOAD = 3
RECORD_REFERENTS = 4


class HeapObject(NamedTuple):
    # Keep size first so that we can sort a list by size easily.
    size: str
    addr: int
    typename: str
    referents: list[int]
    referrers: list[int]
    payload: str | None = None


def _scanheap(filename: str) -> dict[int, HeapObject]:
    typenames: dict[int, str] = {}
    live_objects: dict[int, HeapObject] = {}
    if filename.endswith(".gz"):
        file = gzip.open(filename, "rb")
    else:
        file = open(filename, "rb")
    with file as f:
        while True:
            (record_kind,) = struct.unpack("B", f.read(1))
            if record_kind == RECORD_DONE:
                # !B
                break
            elif record_kind == RECORD_TYPE:
                # !BQH{len(typename)}s
                objtype_addr, objtype_len = struct.unpack("!QH", f.read(10))
                typenames[objtype_addr] = f.read(objtype_len).decode("utf-8")
            elif record_kind == RECORD_OBJECT:
                # !BQQL
                addr, objtype_addr, size = struct.unpack("!QQL", f.read(20))
                live_objects[addr] = HeapObject(
                    addr=addr,
                    typename=typenames[objtype_addr],
                    size=size,
                    referents=[],
                    referrers=[],
                )
            elif record_kind == RECORD_OBJECT_WITH_PAYLOAD:
                # !BQQLH{len(payload)}s
                addr, objtype_addr, size, payload_len = struct.unpack(
                    "!QQLH", f.read(22)
                )
                payload = f.read(payload_len).decode("utf-8", "replace")
                live_objects[addr] = HeapObject(
                    addr=addr,
                    typename=typenames[objtype_addr],
                    size=size,
                    payload=payload,
                    referents=[],
                    referrers=[],
                )
            elif record_kind == RECORD_REFERENTS:
                # !BQH{len(referents)}Q
                addr, referents_len = struct.unpack("!QH", f.read(10))
                referents = live_objects[addr].referents
                referents.clear()
                referents.extend(
                    struct.unpack(
                        f"{referents_len}Q",
                        f.read(8 * referents_len).decode("utf-8", "replace"),
                    )
                )
            else:
                logging.fatal("unknown record kind %d", record_kind)
        else:
            logging.warning("incomplete file")
    logging.info("%s: %d live objects scanned", filename, len(live_objects))
    # Now that we have the full graph, fill in the referrers.
    for obj in live_objects:
        for referent in obj.referents:
            live_objects[referent].referrers.append(obj.addr)
    return live_objects


def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--previous-heap-dump",
        default=None,
        help="A previous heap dump. Only live objects that also appear in the previous heap dump will be considered.",
    )
    subparsers = parser.add_subparsers()

    def _top(args: argparse.Namespace) -> None:
        for entry in sorted(live_objects.values(), reverse=True)[
            : args.top_allocations
        ]:
            logging.info(
                "%8d %016x %s %s",
                entry.size,
                entry.addr,
                entry.typename,
                repr(entry.payload) if entry.payload is not None else "",
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

    parser_top = subparsers.add_parser("top", help="Show the top heap objects")
    parser_top.add_argument(
        "--top-allocations",
        default=50,
        help="How many of the biggest allocations to show",
    )
    parser_top.add_argument(
        "--show-parents",
        action="store_true",
        help="Whether to show the parents of the biggest allocations",
    )
    parser_top.add_argument("heap_dump", metavar="heap-dump")
    parser_top.set_defaults(func=_top)

    def _graph(args: argparse.Namespace) -> None:
        pass

    parser_graph = subparsers.add_parser(
        "graph", help="Create a graphviz graph centered on specific types"
    )
    parser_graph.add_argument(
        "--top-allocations",
        default=50,
        help="How many of the biggest allocations to show",
    )
    parser_graph.add_argument(
        "--show-parents",
        action="store_true",
        help="Whether to show the parents of the biggest allocations",
    )
    parser_graph.add_argument("heap_dump", metavar="heap-dump")
    parser_graph.set_defaults(func=_graph)
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

    args.func(args)


if __name__ == "__main__":
    _main()
