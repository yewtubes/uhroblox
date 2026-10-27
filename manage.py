"""Command-line administration; never serves a custom web page."""
import argparse
import getpass
from pathlib import Path
from storage import Store

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--database',type=Path,default=Path(__file__).resolve().parent/'data'/'platform.sqlite3')
    commands=ap.add_subparsers(dest='command',required=True)
    create_user=commands.add_parser('create-user')
    create_user.add_argument('username')
    create_asset=commands.add_parser('create-asset',help='Create a local catalog record; does not supply asset bytes or thumbnails')
    create_asset.add_argument('--owner',type=int,required=True)
    create_asset.add_argument('--type',dest='asset_type',type=int,required=True)
    create_asset.add_argument('--name',required=True)
    create_asset.add_argument('--price',type=int,default=0)
    grant=commands.add_parser('grant-asset',help='Grant an existing local catalog record to an independent user')
    grant.add_argument('--user',type=int,required=True)
    grant.add_argument('--asset',type=int,required=True)
    args = ap.parse_args()
    store = Store(args.database)
    try:
        if args.command=='create-user':
            password = getpass.getpass('New independent local password: ')
            if password != getpass.getpass('Confirm: '):
                raise SystemExit('Passwords do not match')
            print('Created independent local user', store.create(args.username, password))
        elif args.command=='create-asset':
            print('Created local catalog record',store.create_catalog_record(args.name,args.asset_type,args.owner,args.price))
            print('Asset bytes and thumbnails are not configured by this command.')
        elif args.command=='grant-asset':
            print('Granted local asset' if store.grant_asset(args.user,args.asset) else 'Local asset is already owned')
    except ValueError as e:
        raise SystemExit(str(e))
