#!/usr/bin/python
import sys
import array
from sets import Set

class Rc4Solver:

    # This is the k=7 RC4 Solver
    # This solver relies primarily on two data structures: a dictionary that maps the original index to values, and a dictionary that maps the original index to its new location.
    
    def __init__(self):
        self.i = self.ij = self.out = self.leak = 0;
        self.j = Set([0]);
        self.orig_to_value = dict();
        self.orig_to_newloc = dict();
        self.initializeMaps();


    # Prints the two maps: orig_to_value and orig_to_newloc
    def printMaps(self):
        print "printing maps";
        for w in range(11):
            print str(w) + ": " + str(self.orig_to_value[w]);
        print "-------------------------------";
        for w in range(11):
            print str(w) + ": " + str(self.orig_to_newloc[w]);

    # Resolves the possible values of each spot
    def prune_possible_values(self):
        narrowed_down_values = dict();
        num_solved = 0;
        for w in range(256):
            if self.num_values(w) < 256:
                narrowed_down_values[w] = self.get_possible_values(w);
                if self.num_values(w) == 1:
                    num_solved = num_solved + 1;
        if len(narrowed_down_values.keys()) > 0:
            #print "narrowed down values for: " + str(len(narrowed_down_values.keys()));
            if num_solved > 0:
                print "Number of S totally solved for: " + str(num_solved);
            self.reset_maps(narrowed_down_values);
    
    def reset_maps(self, narrowed_down_values):
        self.initializeMaps();
        for k,v in narrowed_down_values.items():
            self.orig_to_value[k] = v;

    # Initializes the two maps
    # At first orig_to_value is defaulted to empty (which means all 0..255 possible values)
    # and at first orig_to_newloc is just the identity, because none of them have been moved yet - i.e. orig_to_newloc[7] = 7 because the new location of the original index 7 is still index 7
    def initializeMaps(self):
        for w in range(256):
            self.orig_to_newloc[w] = Set([w]);
            self.orig_to_value[w] = Set([]);

    # This takes the leak (new j), the old j, and deduces the possible S[i]'s and adds the S[i]'s to the orig_to_value map as long as that index has been moved yet
    def process_leak(self, leak, w):
        possible_si = Set([]);
        jold = self.j;
        for n in self.j:
            possible_si.add((leak - n) % 256);
            possible_si.add((leak - n + 1) % 256);
        self.j = Set([leak, leak+1]);
        
        if (len(self.orig_to_newloc[self.i]) == 1 and self.i in self.orig_to_newloc[self.i]):
            if self.num_values(self.i) < 256:
                possible_si_from_maps = self.get_possible_values(self.i);
                intersection = possible_si & possible_si_from_maps;
                #print '\nexp_si: ' + str(possible_si) + " from maps: " + str(possible_si_from_maps) + ' intersection: ' + str(intersection);
                if len(intersection) == 0:
                    self.orig_to_value[self.i] = possible_si;
                else:
                    self.orig_to_value[self.i] = intersection;

                if len(intersection) == 1:
                    real_si = intersection.pop();
                    count = 0;
                    realnewj = 0;
                    realoldj = 0;
                    # S[i] = jnew - jold, use S[i] to find jnew
                    for new in self.j:
                        for old in jold:
                            diff = (new - old) % 256;
                            if real_si == diff:
                                realnewj = new;
                                realoldj = old;
                                count = count + 1;
                    if count == 1:
                        print "\nnarrowed down S[i] to " + str(real_si);
                        print str(realnewj) + " - " + str(realoldj) + " = " + str(real_si);
                        self.j = Set([realnewj]);
                        self.orig_to_value[self.i] = Set([real_si]);
            else:
                self.orig_to_value[self.i] = possible_si;
        else:
            self.prune_possible_values();
        #print "i: " + str(self.i).zfill(2) +  "  j: " + str(self.j) + "  S[i]: " + str(possible_si);


    # This swaps S[i] and S[j]. In our representation, this changes the orig_to_newloc dictionary. For example, if we were to swap 3 and 7, we would move the contents of orig_to_newloc[3] into orig_to_newloc[7] and vice versa.
    # However, we are often asked to swap 3 and [5 6], meaning that 3 is either being swapped with 5 or 6, we don't know which. To represent this, we move the contents of orig_to_newloc[5] + orig_to_newloc[6] into orig_to_newloc[3] and while removing the old contents of orig_to_newloc[3]. This means that what used to be in index 3 now has a new home, either where index 5 used to live or where index 6 used to live. Then, we ADD the contents of orig_to_newloc[3] to orig_to_newloc[5] and orig_to_newloc[6]. This means that what lives in index 5 is either still there, or now located in where index 3 is.
    # If we know exactly what self.i AND self.j are, then it is just a basic swap of values in the orig_to_values table, as we do not need to bother with using the location table. The location table is used only when we are not certain which index is which swapped with which index.
    def process_swap(self):
        temp = Set([]);
        for n in self.j:
           if len(self.j) == 1:
               temp = self.orig_to_value[n];
               self.orig_to_value[n] = self.orig_to_value[self.i];
               self.orig_to_value[self.i] = temp;
               print "S[j] is now " + str(self.orig_to_value[n]) + ", S[i] is now " + str(self.orig_to_value[self.i]);
               return;
           temp.update(self.orig_to_newloc[n]);
           self.orig_to_newloc[n].update(self.orig_to_newloc[self.i]);
        self.orig_to_newloc[self.i] = temp;


    # Provided with an index, we find all possible values that can be at that index at this snapshot. We do this by finding all the values in the orig_to_newloc dictionary that contain this index. Then we use the keys (the original locations) and look up what possible values those keys contain.
    # If we don't find anything in orig_to_value, it means that that index can be all possible values 0 to 255. We return an empty set to represent this.
    def get_possible_values(self, index):
        possible_indexes = Set([]);
        possible_values = Set([]);
        for k, v in self.orig_to_newloc.items():
            if index in v:
                possible_indexes.add(k);
        for n in possible_indexes:
            if len(self.orig_to_value[n]) == 0:
                return Set([]);
            else:
                possible_values.update(self.orig_to_value[n]);
        #print '\nvalues for index ' + str(index) + ' found: ' + str(possible_values);
        return possible_values;
        
    
    def num_values(self, index):
        possible_indexes = Set([]);
        for k,v in self.orig_to_newloc.items():
            if index in v:
                possible_indexes.add(k);
        possible_values = Set([]);
        for n in possible_indexes:
            if len(self.orig_to_value[n]) == 0:
                return 256;
            else:
                possible_values.update(self.orig_to_value[n]);
        return len(possible_values);


    # This step handles the out = S[S[i] + S[j] % 256] line.
    # We find all possible values of S[i] and S[j]. If neither is "all possible values 0 to 255" (an empty set), then we can narrow down S[i] + S[j] to a reasonable range. Then, we check if we have narrowed down the values of S[S[i] + S[j] % 256] and compare this to the output. If there is only one value out of all possibilities that can work, we can use this information to start crossing out rows in our logic puzzle.
    def process_out(self, out, w):
        if self.num_values(self.i) == 256:
            return;
        #print '\nsi found ' + str(self.i) + ', j is ' + str(self.j);
        self.prune_possible_values();
        possible_sj = Set([]);
        for n in self.j:
            sj_values = self.get_possible_values(n);
            if len(sj_values) == 0:
                return;
            possible_sj.update(sj_values);
        if len(possible_sj) == 0:
            return;
        print 'both si and sj found';
        

    # This function handles a single round in the RC4 code.
    # First we increment i, then we call "process_leak" which gathers information about S[i] from the j = j + S[i] step. Then we call swap, which swaps S[i] and S[j]. Finally, we call process out which handles the out = S[S[i] + S[j] % 256] step.
    def decrypt_round(self, out_byte, leak_byte, w):
        self.out = int(ord(out_byte));
        self.leak = int(ord(leak_byte));
        self.i = (self.i + 1) % 256;
        self.process_leak(self.leak, w);
        self.process_swap();
        self.process_out(self.out, w);
        #self.prune_possible_values();


    # This function has a for loop that calls decrypt_round, which handles a single pass through the RC4 pseudocode. This performs the stream cipher for the specified number of rounds.
    def decrypt(self, leak_file, output_file, rounds):
        leak = open(leak_file, 'r');
        output = open(output_file, 'r');
        leak_bytes = leak.read();
        out_bytes = output.read();
        
        for w in range(rounds):            
            self.decrypt_round(out_bytes[w], leak_bytes[w], w);


    # Runs the function. Currently we have the number of rounds the function will run set to 1000
    def run(self):
        leak_file = 'jbits7.dat';
        output_file = 'stream7.dat';
        num_rounds = 2000;
        self.decrypt(leak_file, output_file, num_rounds);
        print '\ndone for ' + str(num_rounds) + ' rounds\n';
        #self.printMaps();

if __name__ == '__main__':
    Rc4Solver().run();
