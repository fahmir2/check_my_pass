import requests
import hashlib
import sys


def request_api_data(query_data):
    url = 'https://api.pwnedpasswords.com/range/' + query_data
    res = requests.get(url)
    if res.status_code != 200 :
        raise RuntimeError(f'rror fetching: {res.status_code}, check api and try again')
    return res


def get_passwords_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_passwords_leaks_count(response, tail)



def main(args):
    for pswd in args:
        count = pwned_api_check(pswd)
        if count:
            print(f'The {pswd} was found {count} times, change it bro')
        else:
            print(f'{pswd} not found, you are golden mate')
    return 'done!'


if __name__ == '__main__':
    main(sys.argv[1:])
#pwned_api_check('Hola')