def entrypoint(output_path: str):
    import time
    import collections
    import logging
    import json
    import gc
    import struct
    import sys

    SECONDS = int(SECONDS_PLACEHOLDER)
    MAX_PAYLOAD_SIZE = 128
    RECORD_DONE = 0
    RECORD_TYPE = 1
    RECORD_OBJECT = 2
    RECORD_OBJECT_WITH_PAYLOAD = 3

    logging.warning("XXX: dump_heap: writing report to %r", output_path)
    logging.warning("XXX: dump_heap: collecting gc")
    gc.collect()
    seen = set()
    seentypes = set()
    strtype_addr = -1
    dicttype_addr = -1
    ignored_addrs = {id(seen), id(seentypes)}
    ignored_addrs.add(id(ignored_addrs))
    logging.warning("XXX: dump_heap: collected gc")

    try:
        with open(output_path, "wb") as output_file:
            queue = [(0, o) for o in gc.get_objects()]
            x = 0
            totalsize = 0

            while queue:
                if x % 100_000 == 0:
                    logging.warning(
                        "XXX: dump_heap: %d / %d (%5.2f MiB)",
                        x,
                        len(queue),
                        totalsize / 1024.0 / 1024.0,
                    )
                x += 1

                parent_addr, obj = queue.pop()
                addr = id(obj)
                if addr in ignored_addrs:
                    # We don't want to track the objects we own.
                    continue
                objtype = type(obj)
                objtype_addr = id(objtype)
                if objtype not in seentypes:
                    typename = (f"{objtype.__module__}.{objtype.__name__}").encode(
                        "utf-8",
                        "replace",
                    )
                    if typename == "builtins.str":
                        strtype_addr = objtype_addr
                    elif typename == "builtins.dict":
                        dicttype_addr = objtype_addr
                    output_file.write(
                        struct.pack(
                            f"!BQH{len(typename)}s",
                            RECORD_TYPE,
                            objtype_addr,
                            len(typename),
                            typename,
                        )
                    )
                    seentypes.add(objtype)

                if addr in seen:
                    continue
                seen.add(addr)
                size = sys.getsizeof(obj, 0)
                totalsize += size
                try:
                    if isinstance(obj, str):
                        if len(obj) <= MAX_PAYLOAD_SIZE:
                            payload = obj.encode("utf-8", "replace")
                        else:
                            payload = obj[:MAX_PAYLOAD_SIZE].encode("utf-8", "replace")
                        if len(payload) > MAX_PAYLOAD_SIZE:
                            payload = payload[:MAX_PAYLOAD_SIZE]
                        output_file.write(
                            struct.pack(
                                f"!BQQQLH{len(payload)}s",
                                RECORD_OBJECT_WITH_PAYLOAD,
                                addr,
                                parent_addr,
                                objtype_addr,
                                size,
                                len(payload),
                                payload,
                            )
                        )
                    elif isinstance(obj, dict):
                        payload_entries: list[bytes] = []
                        payload_length = 0
                        for key in obj.keys():
                            if isinstance(key, bytes):
                                if len(key) > MAX_PAYLOAD_SIZE:
                                    key_bytes
                                else:
                                    key_bytes = key[:MAX_PAYLOAD_SIZE]
                            elif isinstance(key, str):
                                if len(key) > MAX_PAYLOAD_SIZE:
                                    key_bytes = key[:MAX_PAYLOAD_SIZE].encode(
                                        "utf-8", "replace"
                                    )
                                else:
                                    key_bytes = key.encode("utf-8", "replace")
                            else:
                                key_str = str(key)
                                if len(key_str) > MAX_PAYLOAD_SIZE:
                                    key_bytes = key_str[:MAX_PAYLOAD_SIZE].encode(
                                        "utf-8", "replace"
                                    )
                                else:
                                    key_bytes = key_str.encode("utf-8", "replace")
                            payload_entries.append(key_bytes)
                            payload_length += len(key_bytes) + 1
                            if payload_length > MAX_PAYLOAD_SIZE:
                                break
                        payload = b",".join(payload_entries)
                        if len(payload) > MAX_PAYLOAD_SIZE:
                            payload = payload[:MAX_PAYLOAD_SIZE]
                        output_file.write(
                            struct.pack(
                                f"!BQQQLH{len(payload)}s",
                                RECORD_OBJECT_WITH_PAYLOAD,
                                addr,
                                parent_addr,
                                objtype_addr,
                                size,
                                len(payload),
                                payload,
                            )
                        )
                    else:
                        output_file.write(
                            struct.pack(
                                "!BQQQL",
                                RECORD_OBJECT,
                                addr,
                                parent_addr,
                                objtype_addr,
                                size,
                            )
                        )
                except:
                    output_file.write(
                        struct.pack(
                            "!BQQQL",
                            RECORD_OBJECT,
                            addr,
                            parent_addr,
                            objtype_addr,
                            size,
                        )
                    )

                for child_addr in gc.get_referents((obj)):
                    queue.append((addr, child_addr))

            output_file.write(struct.pack("!B", RECORD_DONE))

            logging.warning(
                "XXX: dump_heap: %d / %d (%5.2f MiB)",
                x,
                len(queue),
                totalsize / 1024.0 / 1024.0,
            )
    except:
        logging.exception("XXX: dump_heap: failed to collect")
        raise
    finally:
        del seen
        del seentypes
        del ignored_addrs
