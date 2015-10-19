#!/Users/srijon/workspace/pyProject/virtualEnv/bin/python
import argparse
import sys
import os

import keepassx.main as kpm
import keepassx.db as kpmdb
import pyperclip

import igtkp_config as config

__version__ = '1.0'

print os.getlogin()

def msg(p_msg,p_flag=0):
    '''This function is for debug message into std.out'''
    print p_msg
    if p_flag > 0:
        sys.exit(p_flag)

def isnotempty(param):
    try:
        assert (isinstance(param,str))
        if (param is not None) and (param.__len__() != 0):
            return True
    except Exception:
        return False

def validate_env_setup(args):
    if not os.path.isfile(args.key_file):
        msg('KP_KEY_FILE file not found', 1)

    if not os.path.isfile(args.db_file):
        msg('KP_DB_FILE file not found', 1)

    os.environ.__setitem__('KP_INSECURE_PASSWORD', '')

    if not (os.path.isfile(args.usr_key_file)):
        msg('%s file not found' % args.usr_key_file, 1)

    if not (os.path.isfile(args.usr_db_file)):
        msg('%s file not found' % args.usr_key_file, 1)

def load_setup(args):
    '''
    :param args:
    :return: Nothing

    This function loads the default values of the required variables and overrides with the config file settings
    '''

    if 'KP_KEY_FILE' in os.environ:
        args.key_file = os.path.expanduser(os.environ['KP_KEY_FILE'])
    if 'KP_DB_FILE' in os.environ:
        args.db_file = os.path.expanduser(os.environ['KP_DB_FILE'])
    if 'KP_USR_DB_FILE' in os.environ:
        args.usr_db_file = os.path.expanduser(os.environ['KP_USR_DB_FILE'])
    args.usr_key_file = os.path.expanduser('~/user.key')

    # Override with Config file properties
    if isnotempty(config.IGTKP_KEY_FILE):
        args.key_file = os.path.expanduser(config.IGTKP_KEY_FILE)
    if isnotempty(config.IGTKP_DB_FILE):
        args.db_file = os.path.expanduser(config.IGTKP_DB_FILE)
    if isnotempty(config.USER_KEY_FILE):
        args.usr_key_file = os.path.expanduser(config.USER_KEY_FILE)
    if isnotempty(config.USER_DB_FILE):
        args.usr_db_file = os.path.expanduser(config.USER_DB_FILE)

def create_db(db_file_path , key_file_path):
    if os.path.isfile(db_file_path):
        _db_file_ = open(db_file_path,'rb')

    if os.path.isfile(key_file_path):
        _key_file_ = open(key_file_path, 'rb')

    return kpmdb.Database(contents=_db_file_.read(), password='', key_file_contents= _key_file_.read())

def fetch_entry(p_db_file , p_key_file, p_srch_key):
    ''' Reads an entry from keepass db by matching Title,Uid or FuzzySearch '''

    if not (os.path.isfile(p_db_file)):
        msg('DB file not found ',1)
    if not (os.path.isfile(p_key_file)):
        msg('KEY file not found ',1)

    db = create_db(p_db_file , p_key_file)
    try:
        entry = kpm._search_for_entry(db, p_srch_key)[0]  # First Entry , TBD hardcoded
    except kpm.EntryNotFoundError as e:
        msg(e.message, 1)

    entrydict = {'uname': getattr(entry,'username') , 'notes':getattr(entry,'notes')}
    pyperclip.copy(entry.password)
    msg('Copied to clipboard')

    return entrydict

def is_user_authorized(args):
    entrydict = fetch_entry(p_key_file=args.usr_key_file, p_db_file=args.usr_db_file, p_srch_key=os.getlogin())
    storepwd = pyperclip.paste()

    try:
        if isnotempty(storepwd):
            if 'notes' in entrydict.keys():
                if entrydict['notes'].__str__().upper() == 'IS_USR_PWD_KEY=YES':
                    if storepwd.split(',')[0].upper().endswith('.KEY'):
                        args.key_file=storepwd.split(',')[0]
                    elif storepwd.split(',')[0].upper().endswith('.KDB'):
                        args.db_file=storepwd.split(',')[0]

                    if storepwd.split(',')[1].upper().endswith('.KEY'):
                        args.key_file=storepwd.split(',')[1]
                    elif storepwd.split(',')[1].upper().endswith('.KDB'):
                        args.db_file=storepwd.split(',')[1]

        return True
    except Exception as e:
        msg(e.message)
        return False

def do_get(args):
    ''' Function called after parsing the arguments from command line '''
    # Validate Input
    v_input = args.hostname
    assert isinstance(v_input, str)

    if v_input not in config.COMPONENT_LIST:
        msg('Invalid argument , choose from %s' % (config.COMPONENT_LIST.__str__()) , 1)

    # Load variables
    load_setup(args)

    # Validate User Env Setup
    validate_env_setup(args)

    # Validate Authorized user
    '''All authorized users will be listed in a KeePass DB
    Validate the id of the current user as igttst01 , igtprd01 etc..
    if yes then fetch the Notes which will store KP_DB_FILE and KP_KEY_FILE paths with CSV format
    Using that in memory fetch the password of the Asset user has requested for
    '''

    # Fetch the record
    if is_user_authorized(args):
        fetch_entry(p_key_file=args.key_file, p_db_file=args.db_file, p_srch_key=args.hostname)

def define_parser(args):
    '''Function to define argument parser object'''
    parser_handler = argparse.ArgumentParser(prog='test', description='This is specific implementation for Ignite program')
    parser_handler.add_argument('-v', '--version', action='version', version='%(prog)s version '+__version__)

    # Adding subparser for each component
    s_parser = parser_handler.add_subparsers()
    get_parser = s_parser.add_parser('get', help='List entries')
    get_parser.add_argument('hostname', action='store', help='Enter the component name')
    get_parser.set_defaults(func=do_get)
    return parser_handler

def main(args=None):
    parser = define_parser(args)
    args = parser.parse_args(args=args)
    try:
        args.func(args)
    except KeyboardInterrupt:
        msg('\n')
        return 1

if __name__ == '__main__':
    main(sys.argv[1:])



