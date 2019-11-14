I wanted some practise in systems programming, crypto and even basic multithreading all at once, so I'm building this simple luks cracker which parses the luks header of a drive, finds the active keys, and then brute forces them using supplied wordlists. Only useful against weak passwords, obviously!

Included in the repo is a pdf specifying the process of luks encrpytion and it's header structure. I would reccomend looking at the table there for a better understanding of what my code is doing. 
