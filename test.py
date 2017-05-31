import json
import argparse
import standardfile.models


def local(args):
    dump = json.load(open(args.file))

    for serialized in dump['items'][:2]:
        item = standardfile.models.load(serialized, args.key)
        print("{}".format(standardfile.models.load(serialized, args.key)))


def remote(args):
    client = standardfile.client.Client(args.email, args.password)

    if args.show_master_key:
        print("{}".format(client.master))
    else:
        for item in client.get():
            print("{}".format(item))


def add_note(args):
    note = standardfile.models.Note(title=args.title, text=args.text)
    client = standardfile.client.Client(args.email, args.password)
    client.post([note])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    cmd_parser = parser.add_subparsers(title="Commands")

    local_parser = cmd_parser.add_parser('local', help="Decrypt local data")
    local_parser.set_defaults(run=local)
    local_parser.add_argument('--file', metavar='FILE.JSON', type=str, required=True)
    local_parser.add_argument('--key', metavar='MASTER', type=str, required=True)

    remote_parser = cmd_parser.add_parser('remote', help="Decrypt remote data")
    remote_parser.set_defaults(run=remote)
    remote_parser.add_argument('--email', metavar='ADDR', type=str, required=True)
    remote_parser.add_argument('--password', metavar='PASS', type=str, required=True)
    remote_parser.add_argument('--show-master-key', action='store_true', default=False)

    add_parser = cmd_parser.add_parser('add', help="Add a note")
    add_parser.set_defaults(run=add_note)
    add_parser.add_argument('--email', metavar='ADDR', type=str, required=True)
    add_parser.add_argument('--password', metavar='PASS', type=str, required=True)
    add_parser.add_argument('--title', type=str, required=True)
    add_parser.add_argument('--text', type=str, required=True)
    add_parser.add_argument('--key', metavar='MASTER', type=str, required=True)

    args = parser.parse_args()
    args.run(args)
