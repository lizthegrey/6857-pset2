#!/usr/bin/python
import sys
import array


class Rc4Solver:
    def __init__(self):
        self.i = self.j = self.ij = self.out = self.leak = self.state_swap = 0;
        self.state = self.initializeState();        

    def initializeState(self):
        rc_state = array.array('i');
        for w in range(256):
            rc_state.append(-1);
        return rc_state;

    def swap_state(self,i,j):
        self.state_swap = self.state[i];
        self.state[i] = self.state[j];
        self.state[j] = self.state_swap;

    def solved_state(self):
        for w in range(len(self.state)):
            if (self.state[w] == -1):
                return False;
        return True;

    def check_round(self, out_byte, leak_byte):
        self.i = (self.i + 1) % 256;
        self.j = (self.j + self.state[self.i]) % 256;
        self.swap_state(self.i,self.j);
        self.out = self.state[(self.state[self.i]+self.state[self.j])%256];
        if (self.out != int(ord(out_byte))):
            print "Not a match";
        #print "expected: " + str(int(ord(out_byte))) + " actual: " + str(self.out);
        #print (self.out == int(ord(out_byte)));
        #print "expected: " + str(int(ord(leak_byte))) + " actual: " + str(self.j);
        
    def check_solution(self, leak_bytes, out_bytes, w):
        print "\nChecking solution...";
        for w in range(w, len(out_bytes)):
            self.check_round(out_bytes[w], leak_bytes[w]);

    def decrypt_round(self, out_byte, leak_byte):
        self.out = int(ord(out_byte));
        self.leak = int(ord(leak_byte));
        self.i = (self.i + 1) % 256;
        self.state[self.i] = (self.leak - self.j) % 256;
        self.j = self.leak;
        self.swap_state(self.i,self.j);
        if (self.state[self.i] > -1 and self.state[self.j] > -1):
            self.ij = (self.state[self.i] + self.state[self.j]) % 256;
            self.state[self.ij] = self.out;
        print str(self.i).zfill(3) + " | " + str(self.j).zfill(3) + " | " + str(self.out).zfill(3) + " | " + str(self.state[self.j]).zfill(3);


    def decrypt(self, leak_file, output_file, rounds):
        leak = open(leak_file, 'r');
        output = open(output_file, 'r');
        leak_bytes = leak.read();
        out_bytes = output.read();
        
        print '\n i     j    out  S[j]\n';
        for w in range(rounds):            
            self.decrypt_round(out_bytes[w], leak_bytes[w]);
            if (self.solved_state()):
                w = w + 1;
                break;
        
        print "\n" + str(self.state);
        print "\nnumber of rounds to solve state: " + str(w) + "\n";
        self.check_solution(leak_bytes, out_bytes, w);

    def run(self):
        leak_file = 'jbits8.dat';
        output_file = 'stream8.dat';
        num_rounds = 1000;
        self.decrypt(leak_file, output_file, num_rounds);
        

if __name__ == '__main__':
    Rc4Solver().run();
