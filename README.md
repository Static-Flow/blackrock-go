# blackrock-go
This is a Golang port of the BlackRock cipher from the [Masscan](https://github.com/robertdavidgraham/masscan) project

A thorough explanation of the uses for BlackRock can be found [here](https://github.com/robertdavidgraham/masscan/#randomization) but the jist is that given an index over a finite list 
such a the numbers [0...99] BlackRock will randomize the index while still visiting all values. This allows us to ramdonly walk a list of values without shuffling the list itself.
<br>
<Br>
Example:

```
input := []int{0,1,2,3,4,5,6,7,8,9}
rng := rand.New(rand.NewSource(time.Now().UnixNano()))
blackRock := InitBlackrock(uint64(len(input)),rng.Uint64(),4)
for i:=0; i < len(input); i++ {
  fmt.Println(input[blackRock.Shuffle(uint64(i))])
}
```
<br>
Output: (note, yours may be different due to the seed)
<br>
Notice the list is iterated sequencially but the output is randomzied

```
2
3
4
5
6
7
8
9
1
0
```
