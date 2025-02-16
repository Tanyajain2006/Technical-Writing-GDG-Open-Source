Common Algorithms and Their Complexities

This document lists various algorithms and their time/space complexities. Some complexities are missing - can you help fill them in?

1. Linear Search
Description: Sequentially checks each element in a list until a match is found or the end of list is reached.
- Best case: O(1) (element found at the start).
- Worst case: O(n) (element found at the end or not found).
- Recursive space complexity: O(n) due to function call stack.


2. Binary Search
Description: Repeatedly divides a sorted array in half, eliminating the half that cannot contain the target value.
- Best case: O(1) (middle element is the target).
- Worst case: O(log n) (keep dividing search space).
- Recursive space complexity: O(log n) (recursion stack depth).

3. Bubble Sort
Description: Repeatedly steps through the list, compares adjacent elements and swaps them if they are in the wrong order.
- Best case: O(n) (already sorted array).
- Worst case: O(n²) (comparing every pair).
- Recursive space complexity: O(n) (function calls).

**Table explaning the complexitites**

| Algorithm     | Approach   | Best Case Time | Average Case Time | Worst Case Time | Space Complexity |
|--------------|-----------|----------------|--------------------|-----------------|------------------|
| **Linear Search** | Iterative  | O(1)          | O(n)              | O(n)            | O(1)             |
|              | Recursive  | O(1)          | O(n)              | O(n)            | O(n) (due to recursion stack) |
| **Binary Search** | Iterative  | O(1)          | O(log n)          | O(log n)        | O(1)             |
|              | Recursive  | O(1)          | O(log n)          | O(log n)        | O(log n) (due to recursion stack) |
| **Bubble Sort** | Iterative  | O(n)          | O(n²)             | O(n²)           | O(1)             |
|               | Recursive  | O(n)          | O(n²)             | O(n²)           | O(n) (due to recursion stack) |



4. Selection Sort
Description: Divides the input list into a sorted and an unsorted region, repeatedly selects the smallest element from the unsorted region to add to the sorted region.
Time Complexity: O(n²)
Space Complexity: O(1)


5. Insertion Sort
Description: Builds the final sorted array one item at a time, by repeatedly inserting a new element into the sorted portion of the array.
Time Complexity: 
-Best Case: O(n) 
-Average & Worst Case: O(n²)
Space Complexity: O(1)


6. Merge Sort
Description: Divides the array into two halves, recursively sorts them, and then merges the sorted halves.

**Working Principle**
- Divide: The array is recursively divided into two halves until each subarray has one element.
- Conquer: The subarrays are sorted recursively.
- Combine: The sorted subarrays are merged to form the final sorted array.

Time Complexity: 

| Case| Complexity |
|-----|------------|
| Best Case| O(n log n) |
| Average Case | O(n log n) |
| Worst Case | O(n log n) |

Since the array is divided into two halves at each step and merging takes O(n) time, the total time complexity is O(n log n).

Space Complexity:
- Merge Sort requires O(n) auxiliary space due to the temporary arrays used for merging.
-  The recursive calls contribute to an additional O(log n) space complexity for the function call stack.

7. Quick Sort
Description: Selects a 'pivot' element and partitions the other elements into two sub-arrays according to whether they are less than or greater than the pivot.
Quick Sort is a **divide-and-conquer sorting algorithm** that selects a pivot element and partitions the array into two subarrays:  
- One with elements smaller than the pivot  
- Another with elements greater than the pivot
  
It then recursively sorts both subarrays.

**Time Complexity:**
- **Best Case:** \(O(n log n)\) → Occurs when the pivot divides the array into two nearly equal halves, leading to balanced recursion.
- **Average Case:** \(O(n log n)\) → On average, random pivots tend to create balanced partitions.
- **Worst Case:** \(O(n^2)\) → Occurs when the pivot always picks the smallest or largest element, leading to highly unbalanced partitions.

**Space Complexity:**
- **In-place implementation:** \(O(log n)\) due to recursive calls in the best and average cases.
- **Worst Case:** \(O(n)\) if recursion depth reaches \(n\) in an unbalanced partition.
- **Extra space (if using additional arrays):** \(O(n)\), but this is not typical in in-place Quick Sort.

**Working Principle**
- Divide: A pivot element is chosen, and the array is partitioned such that elements smaller than the pivot are placed on the left and larger elements on the right.
- Conquer: Quick Sort is recursively applied to the left and right partitions.
- Combine: The sorted partitions are combined (implicitly achieved through recursion).

Time Complexity: 

| Case | Complexity |
|-----|------------|
| Best Case | O(n log n) |
|Average Case | O(n log n) |
| Worst Case | O(n^2) |

- The worst-case occurs when the pivot consistently picks the smallest or largest element, leading to unbalanced partitions.
- Choosing an optimal pivot (e.g., median of three) improves efficiency.

Space Complexity:
- In-place sorting: Quick Sort generally requires O(log n) space for recursive function calls.
- In the worst case, the recursive depth may be O(n) (if partitions are highly unbalanced).
- No additional auxiliary arrays are needed, unlike Merge Sort.

Merge Sort and Quick Sort are two classic examples of **Divide and Conquer** algorithms used for sorting. Divide and Conquer is a fundamental algorithm design paradigm that breaks a problem into smaller subproblems, solves them independently, and then combines their solutions to solve the original problem. 

**Comparison Table**

| Feature | Merge Sort | Quick Sort |
|---------|------------|------------|
| Time Complexity (Best/Average) | O(n log n) | O(n log n) | 
| Time Complexity (Worst) | O(n log n) | O(n^2) |
| Space Complexity | O(n) | O(log n) |
| Stability | Stable | Unstable (in some implementations) |
| In-Place Sorting | No | Yes |

**Conclusion**
- Merge Sort is more suitable for linked lists and cases where stable sorting is required, despite its higher space complexity.
- Quick Sort is preferred for in-place sorting and average-case efficiency, but worst-case performance can be poor without an optimal pivot selection strategy.
- Both algorithms have their own strengths and are widely used in different applications depending on the requirements of stability, space constraints, and performance.


8. Breadth-First Search (BFS)
   
Description: Explores a graph level by level, visiting all neighbors of a node before moving to the next level.
BFS is a **graph traversal algorithm** that explores nodes **level by level**, making it suitable for shortest path problems in an unweighted graph.  
It uses a **queue** to keep track of nodes to be visited.

**Time Complexity:**
- **Adjacency List Representation:** \(O(V + E)\)  
  - Each vertex is processed once, and each edge is explored once.
- **Adjacency Matrix Representation:** \(O(V^2)\)  
  - Checking all adjacent vertices takes \(O(V)\) per vertex.

**Space Complexity:**
- **Queue:** \(O(V)\) → In the worst case, all vertices at the largest level are stored.
- **Visited Array:** \(O(V)\) → Stores visited nodes.
- **Adjacency List Storage:** \(O(V + E)\)
- **Total:** \(O(V + E)\) for adjacency list representation.

**Visualization of BFS Traversal:**

![image](https://github.com/user-attachments/assets/78aeb7d2-289d-4668-a709-ed523c5e382a)

![image](https://github.com/user-attachments/assets/8f1f6b1f-16b5-4831-b705-d383362cd1fa)

9. Depth-First Search (DFS)
    
Description: Explores a graph by going as deep as possible along each branch before backtracking. 
DFS is a **graph traversal algorithm** that explores as deeply as possible before backtracking. It is used in applications like **topological sorting, cycle detection, and pathfinding**.  
It can be implemented **recursively** (using the call stack) or **iteratively** (using an explicit stack).

**Time Complexity:**
- **Adjacency List Representation:** \(O(V + E)\)  
  - Each vertex and edge is visited once.
- **Adjacency Matrix Representation:** \(O(V^2)\)  
  - Checking adjacency takes \(O(V)\) per vertex.

**Space Complexity:**
- **Recursive Call Stack:**
  - **Worst case:** \(O(V)\) → If the graph is skewed like a linked list.
  - **Best case:** \(O(\log V)\) → If the graph is balanced.
- **Visited Array:** \(O(V)\)
- **Adjacency List Storage:** \(O(V + E)\)
- **Total:** \(O(V + E)\), with additional \(O(V)\) recursion stack in the worst case.

**Visualization of DFS Traversal:**

![image](https://github.com/user-attachments/assets/78aeb7d2-289d-4668-a709-ed523c5e382a)

![image](https://github.com/user-attachments/assets/0ddbf998-9530-4425-ae1b-cc50c9c967c6)


11. Dijkstra's Algorithm
Description: Finds the shortest paths between nodes in a graph with non-negative edge weights.

Working Principle:
Uses a priority queue (min-heap) to iteratively pick the node with the smallest known distance, updating distances to its neighbors until all shortest paths are found.

Time Complexity: 
Best Case: O(V log V)
Average Case: O((V + E) log V)
Worst Case: O(V^2)
Space Complexity: O(V + E)



11. Floyd-Warshall Algorithm
Description: Finds shortest paths between all pairs of vertices in a weighted graph.

Working Principle:
Uses dynamic programming to iteratively update shortest path distances by checking if an intermediate vertex provides a shorter route between two nodes.

Time Complexity: 
Best Case: O(V^3)
Average Case: O(V^3)
Worst Case: O(V^3)
Space Complexity: O(V^2)


12. Knapsack Problem (Dynamic Programming)
Description: Determines the most valuable combination of items that can be carried in a knapsack of limited weight.

Working Principle: Uses a 2D array to store the maximum value obtainable for each item and weight combination, iterating through possible item choices to determine the optimal selection.

Time Complexity: 
Best Case: O(nW)
Average Case: O(nW)
Worst Case: O(nW)
Space Complexity: O(nW)


13. Fibonacci Sequence (Recursive)

**Description:** Calculates the nth Fibonacci number using recursive calls. This results in Recurrence relation:
- F(n)=F(n-1) + F(n-2)

**Time Complexity:** O(2^n)
- Each Fibonacci number is calculated using 2 recursive calls.
- This creates an exponential number of function calls.
- The recurrence tree has a depth of n and at each level, the number of calls doubles, leading to exponential time complexity.
  
```java
public static int fib(int n) {
		if(n==0) {
			return 0;
		}
		
		if(n==1) {
			return 1;
		}
		
		return fib(n-1)+fib(n-2);
  }
```

**Space Complexity:** O(n)
- The recursion stack has a depth of n as the function calls reach to the base case.
- An example representation:
  ![Image](https://github.com/user-attachments/assets/107309a2-4d7e-4f92-8788-5936cccd1dda)


14. Fibonacci Sequence (Dynamic Programming)

    
**Description:** Calculates the nth Fibonacci number using a bottom-up approach with memoization.

**Time Complexity:** O(n) 
- Each Fibonacci number is calculated only once and stored in memory for re-use to avoid redundant calculations.
  
**Space Complexity:**O(n)
- An array of size n+1 (since 0 based indexing) used to store the values.

```java
public static int fib_memo(int n) {
		int memo[]=new int[n+1];
		memo[0]=0;
		memo[1]=1;
		
		if(n==0 || n==1) {
			return n;
		}
		
		for(int i=2;i<memo.length;i++) {
			memo[i]=memo[i-1]+memo[i-2];
		}
		
		return memo[n];
}
```


15. Matrix Multiplication (Naive)
Description: Multiplies two matrices using the standard row-column multiplication method.
Time Complexity: 
Space Complexity:


Note: For each algorithm, consider:
- Best case scenario
- Average case scenario
- Worst case scenario
- Any space complexity variations based on implementation

Can you help fill in the missing complexities? Create a PR with your solutions!

---
### **Recursive vs. Iterative Algorithms: Space Complexity Comparison**  

Algorithms can be implemented using **recursion** or **iteration**, but they differ in **space complexity** due to how they manage memory.  

---

## **1. Understanding Space Complexity in Recursion**  
### How Recursion Uses Memory:  
- Recursive algorithms use the **call stack** to store function calls until they return.  
- Each recursive call **adds a new stack frame**, increasing space usage.  
- The recursion **depth determines space complexity**.  

### **Example: Quick Sort (Recursive)**
- **Space Complexity:** `O(log n)` (average case), `O(n)` (worst case when unbalanced).  
- **Reason:** The recursive function calls store partitions on the stack.  

#### **Pseudocode for Recursive Quick Sort**
```python
function quickSort(arr, low, high):
    if low < high:
        pivotIndex = partition(arr, low, high)
        quickSort(arr, low, pivotIndex - 1)  # Recursive call for left subarray
        quickSort(arr, pivotIndex + 1, high) # Recursive call for right subarray
```
- **Recursive Depth:** `O(log n)` in the best case but `O(n)` in the worst case (skewed partitioning).  
- **Memory Usage:** Each function call adds a new stack frame.  

---

## **2. Understanding Space Complexity in Iterative Algorithms**  
### How Iteration Saves Space:  
- Iterative algorithms **do not use the call stack** for recursive function calls.  
- Instead, they use **loop constructs**, requiring **constant space (`O(1)`)** if no extra data structures are needed.  

### **Example: Merge Sort (Iterative)**
- **Space Complexity:** `O(n)` (due to auxiliary array for merging).  
- **Reason:** Avoids recursion stack, but still requires temporary storage for merging.  

#### **Pseudocode for Iterative Merge Sort**
```python
function mergeSortIterative(arr):
    n = length(arr)
    currentSize = 1
    while currentSize < n:
        left = 0
        while left < n-1:
            mid = min(left + currentSize - 1, n-1)
            right = min(left + 2*currentSize - 1, n-1)
            merge(arr, left, mid, right)
            left += 2 * currentSize
        currentSize *= 2
```
- **No recursion stack used** → avoids `O(log n)` recursive call overhead.  
- **Still requires `O(n)` auxiliary space** for merging.  

---

## **3. Comparing Recursive vs. Iterative Implementations**  

| Algorithm | Recursive Space Complexity | Iterative Space Complexity |  
|-----------|---------------------------|---------------------------|  
| Quick Sort | `O(log n)` (best/avg), `O(n)` (worst) | `O(1)` (if stack avoided) |  
| Merge Sort | `O(n)` (auxiliary array + recursion depth) | `O(n)` (auxiliary array) |  
| Fibonacci | `O(n)` (due to recursion depth) | `O(1)` (loop-based) |  
| DFS | `O(h)`, where `h` is tree/graph depth | `O(n)` (if stack used explicitly) |  
| BFS | `O(n)` (queue storage) | `O(n)` (queue storage) |  

---
## **How Recursion Impacts Space Usage with Stack Frames**  

### **What Happens in Memory During Recursion?**  
When a function calls itself recursively, the system **allocates memory** on the **call stack** for each function call. These stack frames store:  
- **Function parameters**  
- **Local variables**  
- **Return address (where to continue execution after returning)**  

Each recursive call **adds a new stack frame**, and these frames remain in memory until the function returns. If recursion is too deep, it can cause **stack overflow**.

---

### **Example: Recursive Fibonacci Calculation**
Let's take a simple recursive Fibonacci function:
```python
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
```
- **Function Calls for `fibonacci(4)`:**  
```
fibonacci(4)  
├── fibonacci(3)  
│   ├── fibonacci(2)  
│   │   ├── fibonacci(1) → returns 1  
│   │   ├── fibonacci(0) → returns 0  
│   ├── fibonacci(1) → returns 1  
├── fibonacci(2)  
│   ├── fibonacci(1) → returns 1  
│   ├── fibonacci(0) → returns 0  
```
- **Stack Frame Growth (Call Stack):**
```
fibonacci(4)
  fibonacci(3)
    fibonacci(2)
      fibonacci(1)  (returns)
      fibonacci(0)  (returns)
    fibonacci(1)  (returns)
  fibonacci(2)
    fibonacci(1)  (returns)
    fibonacci(0)  (returns)
```
- **Space Complexity:** `O(n)` (for call stack depth).  
- **Problem:** Many redundant calls (`fibonacci(2)` appears twice).  

---

### **Recursion vs. Iteration: Call Stack Usage**  
| Approach | Space Complexity | Why? |
|----------|----------------|------|
| **Recursive Fibonacci** | `O(n)` | Each call adds a stack frame until `n` reaches 0. |
| **Iterative Fibonacci** | `O(1)` | Uses only a few variables, no extra function calls. |

---


