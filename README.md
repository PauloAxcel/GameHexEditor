# PyGameHexEd - Python Game Hacking Tool

PyGameHexEd is a powerful, Cheat Engine-like tool built in Python, designed for memory inspection, modification, and game hacking. It leverages `psutil` for process discovery, `pywin32` for deep memory analysis on Windows, and `pyray` for a responsive and intuitive graphical interface.

It excels at targeting emulators by automatically identifying processes based on a whitelist of known emulator executables.

![Screenshot of PyGameHexEd](https://i.imgur.com/rY43hA2.png)

## ✨ Core Features

*   **🎮 Emulator-Aware Process Detection:**
    *   Automatically scans and lists running processes from a curated list of known emulators.
    *   Includes a one-click **Refresh** button to re-scan for new processes without restarting.

*   **🧠 Advanced Memory Analysis (Windows API):**
    *   Goes beyond `psutil` by using `VirtualQueryEx` to get the precise size, type, and state of all memory regions.
    *   **Intelligently identifies** and reads all writable memory blocks, providing a comprehensive view of the process's RAM.
    *   Handles process memory changes gracefully, preventing crashes if a memory region becomes inaccessible during a refresh.

*   **📝 Interactive Hex Viewer:**
    *   "Stitches" all relevant memory regions into a single, contiguous, and smooth-scrolling view.
    *   Displays the real memory **Address**, **Hex** data, **ASCII** representation, and the **File Path** or region type of the underlying memory.
    *   **Live Highlighting:** Any byte that changes is instantly highlighted in red.
    *   **Full Keyboard Navigation:** Use `WASD` to move the selection cursor byte-by-byte. Use **PageUp/PageDown** for fast scrolling and **Up/Down Arrows** to jump between memory region boundaries.
    *   **Mouse Support:** Click to select a byte, or click-and-drag to select a range.

*   **✍️ Live Memory Editing:**
    *   **Direct Hex Editing:** Double-click or press `Q` on a byte to edit its value directly in the hex view.
    *   **Intuitive Editing Flow:** Use arrow keys to commit your change and immediately start editing the adjacent byte.

*   **🔍 Powerful Value Scanner:**
    *   Scan for specific values across the entire mapped memory.
    *   **Multiple Data Types:** Supports `1 Byte`, `2 Bytes`, `4 Bytes`, `Float`, `Hex`, and **`ASCII`** string searches.
    *   **Dual Endian Scanning:** Automatically searches for both **little-endian and big-endian** representations simultaneously for multi-byte types (`Float`, `2/4 Bytes`).
    *   **First Scan & Next Scan:** Perform an initial search and then filter those results with subsequent scans to pinpoint the exact address you need.
    *   **Virtualized & Interactive Results:** The results list is fully scrollable and virtualized, preventing freezes with large result sets. Click any address to instantly jump to it in the hex viewer.

*   **💾 Stored Entries (Cheat List):**
    *   **Store Addresses:** Add addresses from the scanner or directly from the hex viewer (`E` key) to a persistent list.
    *   **Click-to-Navigate:** Click any address in the stored list to jump the memory viewer to that location.
    *   **Value Freezing:** Toggle a checkbox to "freeze" any value, causing the tool to continuously write it to memory, locking it in place.
    *   **Live Editing:** Double-click a stored entry's value to change it on the fly.
    *   **Endian Swapping:** For multi-byte types, click the "Endian" toggle (`L`/`B`) to swap the byte order of the stored value. The "Frozen" feature respects the current endianness.
    *   **Dynamic Type Conversion:** Change the data type of a stored entry at any time, and the tool will re-read the memory and display it correctly.

## 🕹️ Controls

| Key / Action                | Context         | Description                                                              |
| --------------------------- | --------------- | ------------------------------------------------------------------------ |
| **Click**                   | Process List    | Selects a process and opens the memory viewer.                           |
| **Click "Refresh"**         | Process List    | Refreshes the list of running processes.                                 |
| **Mouse Wheel**             | Any List        | Scrolls the list up or down.                                             |
| **WASD Keys**               | Hex Viewer      | Moves the selection cursor one byte at a time.                           |
| **Arrow Up/Down**           | Hex Viewer      | Jumps to the start of the previous/next memory region.                   |
| **Page Up/Down**            | Hex Viewer      | Scrolls the hex view by a large amount.                                  |
| **Click / Drag**            | Hex Viewer      | Selects a byte or a range of bytes.                                      |
| **Double-Click / `Q`**      | Hex Viewer      | Enters edit mode for the selected byte.                                  |
| **`E` Key**                 | Hex Viewer      | Stores the selected address in the "Stored Entries" list.                |
| **`Ctrl+C`**                | Hex Viewer      | Copies the selected bytes to the clipboard as a hex string.              |
| **Click Address**           | Scan Results    | Jumps to the address in the hex viewer and selects it.                   |
| **Click Address**           | Stored Entries  | Jumps to the address in the hex viewer and selects it.                   |
| **Double-Click Value**      | Stored Entries  | Edits the value of the stored entry.                                     |
| **Click Endian Toggle**     | Stored Entries  | Swaps the byte order between Little and Big Endian.                      |
| **Click Checkbox**          | Stored Entries  | Toggles the "frozen" state for the address.                              |
| **Click Type**              | Stored Entries  | Cycles through available data types for the address.                     |
| **Click `X`**               | Stored Entries  | Removes the entry from the list.                                         |

## 🔧 Setup

Ensure you have Python 3 installed, then install the required libraries:

```bash
pip install psutil pyray pywin32 pyperclip
```

## 🚀 How to Use

1.  Run the script from your terminal:
    ```bash
    python PyGameHexEd.py
    ```
2.  Launch a game in your target emulator (e.g., mGBA, DuckStation).
3.  The PyGameHexEd window will automatically detect the emulator and display it. If it doesn't, click the "Refresh" button.
4.  Click on the emulator process in the list.
5.  The Memory Viewer will appear. You can now inspect, scan, and edit the game's memory in real-time.




FUTURE WORK
---
## 🍎 Easy & High-Impact Improvements

These are great next steps that build directly on your existing code and significantly improve usability.

### 1. Save and Load Stored Entries

### 2. "Undo Scan" Functionality
Sometimes a "Next Scan" filters out everything by mistake. An "Undo" button is a lifesaver.

* **How to do it:**
    1.  Create a new global list called `scan_history = []`.
    2.  In `perform_scan`, right before you calculate `new_results_set`, add the current `scan_results` to the history: `scan_history.append(list(scan_results))`.
    3.  Create an "Undo Scan" button. When clicked, it pops the last results from the history: `if scan_history: scan_results = scan_history.pop()`.


## 🚀 Intermediate Features (The Next Level)

### 1. Pointer Scanner
This is the **most important feature** for creating cheats that work after you restart the game. Values like health have dynamic addresses that change each time the game loads. A pointer scanner finds a stable path to that changing address.

* **The Concept:** It finds a static address (which doesn't change) that contains the memory address of your value. It works by finding chains: **Static Address -> Points to Dynamic Address -> Points to Value**.
* **How to do it (High Level):**
    1.  Find the address of a value (e.g., Health at `0xAAAA`).
    2.  Scan the entire memory for any address that holds the value `0xAAAA`. This gives you a list of potential pointers.
    3.  Restart the game. Find the new health address (e.g., `0xBBBB`).
    4.  Of your previous list of pointers, see which one now holds the value `0xBBBB`.
    5.  By repeating this process, you can find a reliable pointer path that leads to your value every time.

### 2. Array of Bytes (AOB) Scanning & Disassembler
This is the first step to modifying game *code*, not just values. For example, instead of freezing your health value, you can find the instruction that *decreases* health (`SUB EAX, 1`) and disable it.

* **How to do it:**
    1.  **AOB Scan:** Your "Hex" scan type is already a basic AOB scan! You can enhance it to support wildcards (e.g., `F3 0F 11 05 ?? ?? ?? 00`, where `??` can be any byte).
    2.  **Disassembler View:** Create a new view that takes a block of memory (like the hex view) and translates the bytes into human-readable Assembly instructions. The Python **`capstone`** library is perfect for this.

---
## 🐲 Expert Features (The Final Bosses)

### 1. Code Injection and Assembly
This is the next step after finding code with an AOB scan. It involves writing your own assembly code and injecting it into the target process to fundamentally change how the game works.

### 2. Debugger Integration
Instead of just reading memory, you can attach a full debugger to the process. This lets you set breakpoints that pause the game when your health value is read or written to, instantly showing you the exact line of code responsible. This requires using the low-level Windows Debugging API.
