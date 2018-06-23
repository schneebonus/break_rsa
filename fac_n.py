from multiprocessing import Pool, TimeoutError
import multiprocessing as mp
import decimal
import argparse
from argparse import RawTextHelpFormatter
from Crypto.PublicKey import RSA

load_per_thread = 10000000	# how many tries should a thread do before dying
max_processes = 0		# default. will be set while programm is running


def guess_p_and_q(e, n, mode):	
	global load_per_thread
	global max_processes

	if trivial_checks(n) != False:
		return trivial_checks(n)
	
	i = 7
	p = 0
	q = 0

	if max_processes == 0:
		try:
			max_processes = mp.cpu_count()
		except NotImplementedError:
			max_processes = 1

	root = int(decimal.Decimal(n).sqrt())
	
	if root % 2 == 0:
		root += 1	# root should not be even (primes are not even and this way we can to steps of size 2).

	max_threads = min(root, load_per_thread * max_processes)

	pool = Pool(processes=max_processes) 

	if mode == "iterative":
		i = 7
		limit = root
	elif mode == "root":
		i = root
		limit = n
	else:
		return None, None

	while i < limit and q == 0 and p == 0:
		print("New round with p in [" + str(i) + ", " + str(i+max_threads) + "]:")
		results = pool.imap_unordered(do_n_loop_steps, range(i, i + max_threads, load_per_thread))
		for possible_p in results:
				loop_solution = possible_p
				if loop_solution != None:
					p = int(loop_solution)
					q = int(n / p)
		i += max_threads
	print("-"*30)
	if p * q == n:
		print("Success! p=" +str(p) +", q=" + str(q) + ", i="+str(i))
		return p,q
	else:
		print("Error! Could not find p and q!")	
		return None, None

def do_n_loop_steps(testp):
	global load_per_thread
	nsteps = load_per_thread
	i = 0
	print("\t- starting thread for p in [" + str(testp) + ", " + str(testp + nsteps) + "]")
	while i < nsteps:
		if loop_step(testp) == None:
			testp += 2
			i += 2
		else:
			return testp
	return None

def loop_step(testp):
	if n % testp == 0:
		return testp
	return None
	

def trivial_checks(n):
	if n % 2 == 0:
		return 2, int(n / 2)
	if n % 3 == 0:
		return 3, int(n / 3)
	if n % 5 == 0:
		return 5, int(n / 5)
	return False;

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m



def get_priv_key(p,q):
	if p != None and q != None:
		print("-"*30)
		phi_n = int((p-1)*(q-1))
		print("phi(n)=(" + str(p) + "-1)*(" + str(q) + "-1)="  + str(phi_n))
		print("e=" + str(e))
		d = modinv(e, phi_n)
		print("d=" + str(d))
		print("-"*30)
		print("private key is:")
		print("("+str(d)+","+str(n)+")")
		return d

if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog='fac_n.py', 
				description='Crack weak public rsa keys and generate private keys:\n' + 
				'- Factor n using brute force.\n' + 
				'- Based on common weak selections of p and q.', 
				epilog='by Mark Schneemann ( factor_n@f5w.de )', formatter_class=RawTextHelpFormatter)
	parser.add_argument('-m', 
		help='mode to find p and q:\n' + 
		'iterative\t- better when p or q are too low\n' + 
		'root\t\t- better when p and q are close to each other',
		choices=["iterative","root"], type=str, default="root")
	parser.add_argument('-file', help='public key file')
	parser.add_argument('-threads', help='amount of threads to use', type=int)
	parser.add_argument('-o', help='output private key pem file', type=str)
	parser.add_argument('-e', help='education mode: e from public key', type=int)
	parser.add_argument('-n', help='education mode: n from public key', type=int)
	args = parser.parse_args()

	valid = True
	if args.file == None and (args.e == None or args.n == None):
		print("Error: Please specify (-file) or (-e and -n)")
		valid = False

	if args.e != None and args.n != None:
		e = args.e
		n = args.n

	if args.file != None:
		f = open(args.file, "r")
		public_key = RSA.importKey(f.read())
		e = public_key.e
		n = public_key.n

	if args.threads != None:
		max_processes = args.threads


	if valid:
		p,q = guess_p_and_q(e, n, args.m)
		d = get_priv_key(p,q)

		if args.o != None:
			rsa = RSA.construct((n, e, d))
			file = open(args.o,"w") 
			file.write(rsa.exportKey('PEM').decode("utf-8"))
			file.close()


