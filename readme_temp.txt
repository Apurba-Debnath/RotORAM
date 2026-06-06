- Almost all the places I have made changes I have tried to add comments. Sometimes those comments also specify exactly what was changed, but thats rare.

So to know what was changed in a function you might need to compare it line by line with the original panacea function if you need to.
    - All comments made by me begin with either:
    - // abheet: ...
    - // NOTE(abheet): ...
    - // TODO(abheet): ...

- Currently only panacea code is migrated, with some functions (around 200 lines of code) remaining. I have not migrated your functions that you added in the oram.rs file. 

Another important thing to note is that there are some mistakes regarding using custom modulus, at some places I am still doing arithmetic using default wrapping behavior. Some of these places I know where they are but I would need to thoroughly go through the entire code to find all places. So correctness cannot be guaranteed.

- the changes are in a readable form, you can try to read and understand them, or suggest some corrections.

I will be trying to port your oram.rs functions and improve correctness.

- There are mostly 4 kinds of changes:
    - Changes internal to a function: these modified functions could be used as earlier
    - Changes in the function arguments: some functions take an extra argument, usually a modulus
    - Changes in function name: rare, but some functions are now with a new name. Use compiler's help, will tell you whether some old function was deleted if you tried to use it. The newer function that replaces it will be near it in the source code.
    - Some functions have been completely deleted: These functions were not being used anywhere so I just commented them out and left for later, if you need any such function then I will update them.
