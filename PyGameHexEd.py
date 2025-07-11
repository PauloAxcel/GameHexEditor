import psutil
from pyray import *
import win32api
import win32process
import pywintypes
import struct
import pyperclip
import os
import ctypes
from ctypes.wintypes import HANDLE, LPVOID, LPWSTR
import win32con
import threading
import time


# --- Configuration ---
screen_width = 1400
screen_height = 820
background_color = Color(245, 245, 245, 255)
text_color = Color(50, 50, 50, 255)
header_color = Color(100, 100, 100, 255)
selection_color = Color(200, 200, 255, 255)
item_height = 20
font_size = 18
placeholder_color = Color(255, 193, 7, 255) # A nice yellow/gold color
HEX_POS_X = 230
TOP_HEIGHT_PX = 55
stored_panel_height = 200
results_panel_y = 300
results_header_height = 25
TOP_HEADER_Y = 50
BOTTOM_HEADER_Y = 40
viewer_height = screen_height - stored_panel_height - 20
scrollbar_area_y, scrollbar_area_height = 85, viewer_height - 85 - 20
viewer_panel_width = screen_width - 250 # Leave space for scanner panel
scanner_panel_width = HEX_POS_X
scanner_panel_x = viewer_panel_width + 20 # 20 pixels padding

## Define the list of game extensions globally
GAME_EXTENSIONS = [
    # Nintendo
    '.gb', '.gbc', '.gba', '.nds', '.3ds', '.cia',
    '.nes', '.sfc', '.smc', '.n64', '.z64',
    '.wii', '.wux', '.wad', '.iso',
    # Sony
    '.iso', '.cso', '.psx', '.ps2',
    # Sega
    '.gg', '.sms', '.gen', '.md', '.smd',
    # Others
    '.rom', '.bin'
]
# Link file extensions to a platform identifier
EXTENSION_TO_PLATFORM = {
    # -- Nintendo --
    '.nes': 'NES', '.fds': 'NES',
    '.sfc': 'SNES', '.smc': 'SNES', '.fig': 'SNES',
    '.gb': 'GAMEBOY', '.gbc': 'GAMEBOY',
    '.gba': 'GBA',
    '.n64': 'N64', '.z64': 'N64', '.v64': 'N64',
    '.gcm': 'GAMECUBE', '.iso': 'GAMECUBE', # ISO is generic
    '.wbfs': 'WII', '.wad': 'WII',
    '.nds': 'NDS', '.srl': 'NDS',
    '.3ds': '3DS', '.cia': '3DS',

    # -- Sony --
    '.psx': 'PS1', '.bin': 'PS1', # BIN is also generic
    '.iso': 'PS2', '.exe': 'PS2', # Re-map ISO to PS2 as it's more common
    '.cso': 'PSP', '.pbp': 'PSP',

    # -- Sega --
    '.sms': 'MASTERSYSTEM',
    '.gg': 'GAMEGEAR',
    '.gen': 'GENESIS', '.md': 'GENESIS', '.smd': 'GENESIS',
    '.32x': '32X',
    '.mcd': 'SEGACD',
    '.chd': 'SATURN_DREAMCAST', '.gdi': 'DREAMCAST', '.cdi': 'DREAMCAST',

    # -- Atari --
    '.a26': 'ATARI2600',
    '.a78': 'ATARI7800',
    '.lnx': 'LYNX',

    # -- Other Consoles --
    '.pce': 'PCENGINE',
    '.ngc': 'NEOGEO',

    # -- Generic Fallback --
    '.rom': 'GENERIC_ROM',
    '.zip': 'GENERIC_ROM'
}
# Link platform identifier to a list of possible RAM sizes in bytes
PLATFORM_RAM_MAP = {
    # -- Nintendo --
    'NES': [2 * 1024],                          # 2 KB
    'SNES': [128 * 1024],                       # 128 KB
    'GAMEBOY': [8 * 1024, 32 * 1024, 16 * 1024],                      # 8 KB
    'GBA': [32 * 1024, 256 * 1024],             # 32 KB IWRAM, 256 KB EWRAM
    'N64': [4 * 1024 * 1024, 8 * 1024 * 1024],   # 4 MB Base, 8 MB w/ Expansion Pak
    'GAMECUBE': [24 * 1024 * 1024],              # 24 MB Main RAM
    'WII': [24 * 1024 * 1024, 64 * 1024 * 1024], # 24 MB Internal, 64 MB External
    'NDS': [4 * 1024 * 1024],                   # 4 MB
    '3DS': [128 * 1024 * 1024],                 # 128 MB

    # -- Sony --
    'PS1': [2 * 1024 * 1024],                   # 2 MB
    'PS2': [32 * 1024 * 1024],                  # 32 MB
    'PSP': [32 * 1024 * 1024, 64 * 1024 * 1024], # 32 MB (PSP-1000), 64 MB (PSP-2000+)

    # -- Sega --
    'MASTERSYSTEM': [8 * 1024],                 # 8 KB
    'GAMEGEAR': [8 * 1024],                     # 8 KB
    'GENESIS': [64 * 1024],                     # 64 KB
    'SEGACD': [768 * 1024],                     # 768 KB Total
    '32X': [256 * 1024],                        # 256 KB
    'SATURN_DREAMCAST': [2 * 1024 * 1024, 16 * 1024 * 1024], # Saturn 2MB, Dreamcast 16MB
    'DREAMCAST': [16 * 1024 * 1024],            # 16 MB

    # -- Atari --
    'ATARI2600': [128],                         # 128 Bytes
    'ATARI7800': [4 * 1024],                    # 4 KB
    'LYNX': [64 * 1024],                        # 64 KB

    # -- Other Consoles --
    'PCENGINE': [8 * 1024],                     # 8 KB
    'NEOGEO': [64 * 1024]                       # 64 KB
}
# Known emulators
KNOWN_EMULATORS = [
    # Sony
    'pcsx2-qt.exe', 'pcsx2.exe', 'rpcs3.exe', 'duckstation-qt-x64-release-msvc.exe',
    # Nintendo
    'mgba.exe', 'vbam.exe', 'dolphin.exe', 'cemu.exe', 'yuzu.exe', 'ryujinx.exe', 'citra-qt.exe',
    # Microsoft
    'xenia.exe', 'xenia_canary.exe',
    # Others
    'retroarch.exe'
]


# --- Application State ---
app_state = "process_list"  # "process_list" or "memory_view"
selected_pid = -1
selected_name = ""
process_handle = None
memory_data = b""
error_message = ""
base_address = 0
refresh_timer = 0.0
REFRESH_INTERVAL = 0.8 # Refresh twice per second (every 0.5 seconds)
font = None
memory_update_thread = None
stop_thread_event = threading.Event()
new_memory_data_from_thread = None
thread_lock = threading.Lock()

# --- Process List State ---
process_list = []
selected_process_index = -1
process_scroll_offset = 0.0

# --- Memory View State ---
memory_regions = {} # Key: address, Value: data bytes
region_boundaries = []
current_viewing_address = 0 # The base address of the region we are currently looking at
key_timers = {} # Dictionary to manage repeat delays for held keys
memory_scroll_offset = 0.0
bytes_per_row = 16
dragging_scrollbar = False
selection_start = -1
selection_end = -1
editing_offset = -1  # -1 means not editing, otherwise stores the byte offset
edit_buffer = ""     # Stores the text while editing a hex value

# --- Memory Scanner State ---
scan_value_text = ""
scan_results = []
active_input = False
scan_type = "Int"
scan_results_scroll_offset = 0.0
scan_data_type = "Hex" # Default scan type
last_click_time = 0.0
DOUBLE_CLICK_INTERVAL = 0.25 # Time in seconds for a double-click
scan_comparison_type = "==" # New: "==", "!=", "<", ">"
previous_scan_memory_data = b"" # New: Snapshot of memory from the last scan
scanner_status_message = "Enter a value to scan" # New variable

# --- Stored Entries State ---
stored_entries = [] # List of {'address': int, 'value': bytes, 'type': str}
stored_entries_scroll_offset = 0.0
stored_entries_last_click_time = 0.0 # For double-click detection
dragging_stored_scrollbar = False # NEW: For stored entries scrollbar

# --- Change Highlighting State ---
prev_memory_data = b""
changed_bytes = {} # Key: address, Value: time remaining for highlight
HIGHLIGHT_DURATION = 1.0 # How many seconds the highlight lasts

# pid = 22696
# name = "mGBA.exe"

# Define SIZE_T based on the architecture (32-bit or 64-bit)
if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit
    SIZE_T = ctypes.c_ulonglong
else:  # 32-bit
    SIZE_T = ctypes.c_ulong

# --- NEW: Windows API Setup ---
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", ctypes.c_uint32),
        ("RegionSize", SIZE_T),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [HANDLE, LPVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
VirtualQueryEx.restype = SIZE_T

GetMappedFileNameW = psapi.GetMappedFileNameW
GetMappedFileNameW.argtypes = [HANDLE, LPVOID, LPWSTR, ctypes.c_uint]
GetMappedFileNameW.restype = ctypes.c_uint


def memory_update_thread_func():
    """This function runs in the background to poll for memory changes."""
    global new_memory_data_from_thread, process_handle
    
    while not stop_thread_event.is_set():
        if process_handle:
            data = reread_memory_data()
            if data:
                with thread_lock:
                    global new_memory_data_from_thread
                    new_memory_data_from_thread = data
        
        # Control the refresh rate from the background
        time.sleep(REFRESH_INTERVAL)

    print("Memory update thread has stopped.")


def write_to_memory(offset, hex_string):
    """Writes a new hex value to the process memory and updates the local buffer."""
    global memory_data, process_handle
    if not process_handle or editing_offset == -1:
        return False
        
    try:
        # Convert the hex string (e.g., "C3") to an integer
        new_value = int(hex_string, 16)
        # Pack the integer into a single byte
        byte_to_write = struct.pack('B', new_value)
        
        # Get the true memory address to write to
        true_address = get_true_address(offset)
        
        # Write to the process's memory
        win32process.WriteProcessMemory(process_handle.handle, true_address, byte_to_write)
        
        # Update our local copy immediately
        memory_data[offset] = new_value
        print(f"Successfully wrote {hex_string} to 0x{true_address:X}")
        return True
    except (ValueError, pywintypes.error, struct.error) as e:
        print(f"Error writing to memory: {e}")
        return False
    

def get_mapped_file_name(process_handle, address):
    """Helper to get the file path for a mapped memory region."""
    buffer = ctypes.create_unicode_buffer(260)  # MAX_PATH
    if GetMappedFileNameW(process_handle, address, buffer, 260):
        return buffer.value
    return None


def get_memory_regions(pid):
    """
    Queries all memory regions of a process using the Windows API
    to get their exact sizes, protection, and state.
    """
    try:
        proc_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid
        )
    except pywintypes.error:
        return []

    address = 0
    regions = []
    while True:
        mbi = MEMORY_BASIC_INFORMATION()
        try:
            size = VirtualQueryEx(proc_handle.handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi))
            if size == 0:
                break
            
            # We no longer filter here, we gather all info and filter later
            path = (
                get_mapped_file_name(proc_handle.handle, mbi.BaseAddress)
                if mbi.Type == win32con.MEM_MAPPED
                else None
            )
            regions.append({
                'addr': mbi.BaseAddress,
                'size': mbi.RegionSize,
                'State': mbi.State, # <<< THE FIX IS HERE
                'protect': mbi.Protect,
                'type': mbi.Type,
                'path': path,
            })
            address += mbi.RegionSize
        except Exception:
            break # Reached end of address space
            
    win32api.CloseHandle(proc_handle)
    return regions



def get_offset_from_true_address(true_addr):
    """Translates a true memory address back to an offset in the stitched memory_data."""
    if not region_boundaries:
        return -1

    # Find which region this address belongs to
    # CHANGE: Iterate over dictionaries instead of unpacking tuples
    for region in region_boundaries:
        if region['addr'] <= true_addr < region['addr'] + region['size']:
            offset_in_region = true_addr - region['addr']
            return region['offset'] + offset_in_region

    # Address was not found in any known region
    return -1


def reread_memory_data():
    """
    Re-reads data from known regions. If a region fails, it marks it as
    invalid and fills its space with null bytes to preserve offsets.
    """
    if not process_handle or not region_boundaries:
        return None

    stitched_data_list = []
    for region in region_boundaries:
        # If a region has already failed, don't try reading it again.
        if not region['is_valid']:
            stitched_data_list.append(b'\x00' * region['size']) # Fill with placeholders
            continue

        try:
            # Attempt to read this specific region
            data = win32process.ReadProcessMemory(process_handle.handle, region['addr'], region['size'])
            stitched_data_list.append(data)
        except pywintypes.error:
            # This specific region failed!
            print(f"⚠️ Could not read memory region at 0x{region['addr']:X}. Marking as invalid.")
            region['is_valid'] = False  # Mark it as invalid for future refreshes
            stitched_data_list.append(b'\x00' * region['size']) # Fill with placeholders

    return bytearray(b"".join(stitched_data_list))
    
    
def refresh_process_list():
    """
    Refreshes the process list using a multi-pass filter for high accuracy.
    Pass 1: Checks a whitelist of known emulator executable names.
    Pass 2: Scans for processes that have mapped a known game file type (less reliable).
    Pass 3: Performs heuristic scanning by looking for memory regions that match console RAM sizes.
    """
    global process_list
    process_list = []
    found_pids = set() # Use a set to prevent duplicate entries
    print("Refreshing process list with multi-pass filter...")

    all_processes = list(psutil.process_iter(['pid', 'name']))
    
    # --- Create a flat set of all possible RAM sizes for quick lookups ---
    # all_known_ram_sizes = set()
    # for sizes in PLATFORM_RAM_MAP.values():
    #     all_known_ram_sizes.update(sizes)

    # --- Pass 1: Find processes from the known emulator whitelist ---
    print("  -> Pass 1: Checking known emulator list...")
    for proc in all_processes:
        try:
            if proc.info['name'].lower() in [name.lower() for name in KNOWN_EMULATORS]:
                if proc.info['pid'] not in found_pids:
                    process_list.append(f"{proc.info['pid']}: {proc.info['name']}")
                    found_pids.add(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # --- Pass 2: Find emulators by checking for mapped game files ---
    # This is less reliable but can catch some emulators missed by Pass 1.
    # print("  -> Pass 2: Checking for mapped game files...")
    # for proc in all_processes:
    #     if proc.info['pid'] in found_pids:
    #         continue
    #     try:
    #         p = psutil.Process(proc.info['pid'])
    #         maps = p.memory_maps(grouped=False)
    #         for mem_map in maps:
    #             if mem_map.path and mem_map.path.lower().endswith(tuple(GAME_EXTENSIONS)):
    #                 if proc.info['pid'] not in found_pids:
    #                     process_list.append(f"{proc.info['pid']}: {proc.info['name']}")
    #                     found_pids.add(proc.info['pid'])
    #                     break 
    #     except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
    #         continue

    # --- Pass 3: Heuristic scan for memory regions matching console RAM sizes ---
    # print("  -> Pass 3: Performing heuristic memory scan...")
    # for proc in all_processes:
    #     if proc.info['pid'] in found_pids:
    #         continue
    #     try:
    #         # We only need query permission, which is less restrictive
    #         proc_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, proc.info['pid'])
            
    #         regions = get_memory_regions(proc.info['pid']) # You already have this function!
    #         for region in regions:
    #             # Check for private, writable memory of a known console RAM size
    #             if (region['type'] == win32con.MEM_PRIVATE and
    #                 region['protect'] == win32con.PAGE_READWRITE and
    #                 region['size'] in all_known_ram_sizes):
                    
    #                 if proc.info['pid'] not in found_pids:
    #                     # Found a potential candidate!
    #                     process_list.append(f"{proc.info['pid']}: {proc.info['name']} [Heuristic Match]")
    #                     found_pids.add(proc.info['pid'])
    #                     break # Move to the next process once a match is found
            
    #         win32api.CloseHandle(proc_handle)

    #     except (psutil.NoSuchProcess, psutil.AccessDenied, pywintypes.error):
    #         continue

    print("Refresh complete.")
    
    

def is_key_pressed_with_repeat(key, delay=0.01, initial_delay=0.10):
    """
    Checks for a key press with repeat-on-hold functionality.
    Returns True if the key should trigger an action this frame.
    """
    global key_timers
    
    # Update timer for the key
    if key not in key_timers:
        key_timers[key] = 0.0
    key_timers[key] += get_frame_time()

    if is_key_down(key):
        if is_key_pressed(key):
            key_timers[key] = 0.0 # Reset timer on initial press
            return True
        # Check if the timer has exceeded the appropriate delay
        if key_timers[key] > (delay if key_timers[key] > initial_delay else initial_delay):
            key_timers[key] = 0.0 # Reset timer after firing
            return True
    return False

# pid = selected_pid
def open_process_and_read_memory(pid):
    """
    Opens a process and reads ALL committed, writable memory regions, ensuring
    no critical blocks are missed, similar to how professional tools operate.
    """
    global process_handle, memory_data, region_boundaries, error_message, base_address, memory_update_thread
    memory_data = b""
    region_boundaries.clear()

    try:
        process_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ | win32con.PROCESS_VM_WRITE,
            False, pid
        )

        regions = get_memory_regions(pid)
        print(f"Found {len(regions)} total regions. Reading all writable candidates...")

        candidate_regions = []
        # Find all committed, writable regions, regardless of size.
        for region in regions:
            is_writable = region['protect'] in (
                win32con.PAGE_READWRITE,
                win32con.PAGE_EXECUTE_READWRITE
            )
            if region['State'] == win32con.MEM_COMMIT and is_writable:
                candidate_regions.append(region)

        if not candidate_regions:
            error_message = "Could not find any writable memory blocks."
            win32api.CloseHandle(process_handle)
            return False

        # Sort candidates by their base address for a logical view.
        candidate_regions.sort(key=lambda r: r['addr'])
        stitched_data_list = []
        current_offset = 0

        for region in candidate_regions:
            try:
                # IMPORTANT: Read the entire region, not just a fixed size.
                data = win32process.ReadProcessMemory(process_handle.handle, region['addr'], region['size'])
                
                print(f"  -> Reading region at 0x{region['addr']:X} "
                      f"(Size: {region['size'] / 1024 / 1024:.2f} MB)")

                region_boundaries.append({
                    'offset': current_offset,
                    'addr': region['addr'],
                    'size': len(data),
                    # 'path': f"[Writable Block @ 0x{region['addr']:X}]",
                    'path': f"RAM: 0x{region['addr']:X}]",
                    'is_valid': True
                })
                stitched_data_list.append(data)
                current_offset += len(data)
            except pywintypes.error:
                # This can happen if a region becomes invalid between query and read. It's safe to skip.
                continue

        if not stitched_data_list:
            error_message = "Failed to read from any candidate memory regions."
            win32api.CloseHandle(process_handle)
            return False

        memory_data = bytearray(b"".join(stitched_data_list))
        
        # Start the background polling thread
        stop_thread_event.clear()
        memory_update_thread = threading.Thread(target=memory_update_thread_func, daemon=True)
        memory_update_thread.start()
        
        print("\n✅ Successfully stitched all writable blocks. Polling thread started.")
        return True

    except (psutil.NoSuchProcess, psutil.AccessDenied, pywintypes.error) as e:
        error_message = f"Error: {e}"
        if process_handle:
            win32api.CloseHandle(process_handle)
        return False
    

def draw_process_list_screen():
    global selected_process_index, process_scroll_offset, app_state, selected_pid, error_message, selected_name
    
    # --- REFRESH BUTTON ---
    refresh_button_rect = Rectangle(screen_width - 140, 10, 115, 30)

    # --- Input Handling ---
    mouse_wheel = get_mouse_wheel_move()
    if (get_mouse_y() < screen_height - stored_panel_height - 20):
        process_scroll_offset -= mouse_wheel * item_height
    process_scroll_offset = max(0, min(process_scroll_offset, len(process_list) * item_height - (screen_height - 70)))

    if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT):
        mouse_pos = get_mouse_position()
        # Check for refresh button click
        if check_collision_point_rec(mouse_pos, refresh_button_rect):
            refresh_process_list()
            return # Return to avoid processing list click on the same frame

        mouse_y = get_mouse_y()
        if TOP_HEADER_Y <= mouse_y < screen_height - BOTTOM_HEADER_Y:
            index = int((mouse_y - TOP_HEADER_Y + process_scroll_offset) / item_height)
            if 0 <= index < len(process_list):
                selected_process_index = index
                try:
                    pid_str = process_list[selected_process_index].split(':')[0]
                    name_str = process_list[selected_process_index].split(': ')[1]
                    selected_pid = int(pid_str)
                    selected_name = str(name_str)
                    if open_process_and_read_memory(selected_pid):
                        app_state = "memory_view"
                    else:
                        # Error message is set in the function, so we just stay here
                        pass
                except (ValueError, IndexError):
                    error_message = "Error: Could not parse selected process."

    # --- Drawing ---
    draw_text("Running Processes", 20, 20, 20, header_color)

    # --- DRAW REFRESH BUTTON ---
    draw_rectangle_rec(refresh_button_rect, header_color)
    draw_text("Refresh", int(refresh_button_rect.x + 15), int(refresh_button_rect.y + 5), 20, WHITE)

    draw_line(20, TOP_HEADER_Y-5, screen_width - 20, TOP_HEADER_Y-5, header_color)

    start_index = int(max(0, process_scroll_offset / item_height))
    end_index = int(min(len(process_list), start_index + (screen_height - 70) / item_height))

    for i in range(start_index, end_index):
        y = int(TOP_HEADER_Y + (i * item_height) - process_scroll_offset)
        if i == selected_process_index:
            draw_rectangle(20, y, screen_width - 40, item_height, selection_color)
        draw_text(process_list[i], 25, y + 2, font_size, text_color)

    if error_message:
        draw_text(error_message, 20, screen_height - 30, font_size, RED)
  
  
      
def draw_memory_viewer_screen():
    global app_state, memory_scroll_offset, dragging_scrollbar, refresh_timer, changed_bytes, memory_data, selection_start, selection_end, scan_value_text, active_input, scan_type, scan_results_scroll_offset, font, scan_data_type, last_click_time, editing_offset, edit_buffer, selected_name, scan_comparison_type, scanner_status_message 
    
    # Check if any text field in the stored entries panel is active
    is_editing_stored_entry = any(e.get('is_editing') or e.get('is_editing_des') for e in stored_entries)
    
    # --- 1. HANDLE ALL INPUT AND STATE LOGIC ---

    back_button_rect = Rectangle(float(viewer_panel_width - 120), 20.0, 100.0, 30.0)
    if check_collision_point_rec(get_mouse_position(), back_button_rect) and is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT):
        # --- STOP THE THREAD ---
        stop_thread_event.set()
        if memory_update_thread is not None:
            memory_update_thread.join(timeout=1.0) # Wait for thread to finish
        
        app_state, process_handle = "process_list", None
        if process_handle: win32api.CloseHandle(process_handle)
        return
    if is_key_down(KeyboardKey.KEY_LEFT_CONTROL) and is_key_pressed(KeyboardKey.KEY_C):
        copy_selection_to_clipboard()
    
    delta_time = get_frame_time()
    for addr in list(changed_bytes.keys()):
        changed_bytes[addr] -= delta_time
        if changed_bytes[addr] <= 0: del changed_bytes[addr]

    # --- Scan Panel Logic ---
    scan_input_box = Rectangle(float(scanner_panel_x), 60.0, float(scanner_panel_width - 20), 30.0)
    
    type_btn_y = 100.0
    comparison_btn_y = 140.0 # New Y for comparison buttons
    scan_btn_y = 180.0 # New Y for scan action buttons
    
    btn_width = (scanner_panel_width - 30) / 6 # Adjusted for 6 buttons
    byte1_btn = Rectangle(scanner_panel_x, type_btn_y, btn_width, 30.0)
    byte2_btn = Rectangle(scanner_panel_x + btn_width + 5, type_btn_y, btn_width, 30.0)
    byte4_btn = Rectangle(scanner_panel_x + (btn_width + 5) * 2, type_btn_y, btn_width, 30.0)
    float_btn = Rectangle(scanner_panel_x + (btn_width + 5) * 3, type_btn_y, btn_width, 30.0)
    hex_btn = Rectangle(scanner_panel_x + (btn_width + 5) * 4, type_btn_y, btn_width, 30.0)
    ascii_btn = Rectangle(scanner_panel_x + (btn_width + 5) * 5, type_btn_y, btn_width, 30.0)

    # New Comparison Buttons
    comp_btn_width = (scanner_panel_width - 25) / 4 # 4 buttons, 5px padding
    equal_btn = Rectangle(scanner_panel_x, comparison_btn_y, comp_btn_width, 30.0)
    not_equal_btn = Rectangle(scanner_panel_x + comp_btn_width + 5, comparison_btn_y, comp_btn_width, 30.0)
    greater_btn = Rectangle(scanner_panel_x + (comp_btn_width + 5) * 2, comparison_btn_y, comp_btn_width, 30.0)
    less_btn = Rectangle(scanner_panel_x + (comp_btn_width + 5) * 3, comparison_btn_y, comp_btn_width, 30.0)


    first_scan_button = Rectangle(float(scanner_panel_x), scan_btn_y, float(scanner_panel_width - 20), 30.0)
    next_scan_button = Rectangle(float(scanner_panel_x), scan_btn_y + 40, float(scanner_panel_width - 20), 30.0)
    store_button = Rectangle(float(scanner_panel_x), scan_btn_y + 80, float(scanner_panel_width - 20), 30.0)

    mouse_pos = get_mouse_position()
    
    # Separate mouse press handling to avoid conflicts
    if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT):
        # Scan Input Box Activation
        if check_collision_point_rec(mouse_pos, scan_input_box):
            active_input = True
        else:
            active_input = False
        
        # Data Type Buttons
        if check_collision_point_rec(mouse_pos, byte1_btn): scan_data_type = "1 Byte"
        if check_collision_point_rec(mouse_pos, byte2_btn): scan_data_type = "2 Bytes"
        if check_collision_point_rec(mouse_pos, byte4_btn): scan_data_type = "4 Bytes"
        if check_collision_point_rec(mouse_pos, float_btn): scan_data_type = "Float"
        if check_collision_point_rec(mouse_pos, hex_btn): scan_data_type = "Hex"
        if check_collision_point_rec(mouse_pos, ascii_btn): scan_data_type = "ASCII"

        # New: Comparison Type Buttons
        if check_collision_point_rec(mouse_pos, equal_btn): scan_comparison_type = "=="
        if check_collision_point_rec(mouse_pos, not_equal_btn): scan_comparison_type = "!="
        if check_collision_point_rec(mouse_pos, greater_btn): scan_comparison_type = ">"
        if check_collision_point_rec(mouse_pos, less_btn): scan_comparison_type = "<"


        # Scan Action Buttons
        if check_collision_point_rec(mouse_pos, first_scan_button): perform_scan(first_scan=True)
        if check_collision_point_rec(mouse_pos, next_scan_button): perform_scan(first_scan=False)
        if check_collision_point_rec(mouse_pos, store_button): store_all_scan_results()

    if active_input:
        key = get_char_pressed()
        while key > 0:
            if 32 <= key <= 125: scan_value_text += chr(key)
            key = get_char_pressed()
        
        if is_key_pressed(KeyboardKey.KEY_BACKSPACE): scan_value_text = scan_value_text[:-1]

    # --- Memory Viewer Logic ---
    visible_rows = int(scrollbar_area_height / item_height)
    total_rows = (len(memory_data) + bytes_per_row - 1) // bytes_per_row
    scroll_max = max(0, (total_rows * item_height) - scrollbar_area_height)

    global new_memory_data_from_thread
    local_new_data = None
    with thread_lock:
        if new_memory_data_from_thread is not None:
            local_new_data = new_memory_data_from_thread
            new_memory_data_from_thread = None

    if local_new_data is not None:
        prev_memory_data = memory_data
        memory_data = local_new_data
        
        for entry in stored_entries:
            if not entry['is_editing']:
                offset = get_offset_from_true_address(entry['address'])
                if offset != -1 and offset + len(entry['value']) <= len(memory_data):
                    entry['value'] = memory_data[offset:offset+len(entry['value'])]

        if len(prev_memory_data) == len(memory_data):
            start_byte = int(memory_scroll_offset / item_height) * bytes_per_row
            end_byte = min(start_byte + (visible_rows + 2) * bytes_per_row, len(memory_data))
            for i in range(start_byte, end_byte):
                if memory_data[i] != prev_memory_data[i]:
                    changed_bytes[get_true_address(i)] = HIGHLIGHT_DURATION
    
    memory_scroll_offset = handle_navigation_input(memory_scroll_offset, item_height, scrollbar_area_height, region_boundaries, bytes_per_row, scroll_max)
    memory_scroll_offset, dragging_scrollbar, scrollbar_handle_rect = scroll_bar_logic(memory_scroll_offset, dragging_scrollbar, total_rows, visible_rows, item_height, scrollbar_area_y, scrollbar_area_height, viewer_panel_width)

    # --- Click and Drag Selection ---
    if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT):
        clicked_byte_offset = get_byte_offset_from_mouse(viewer_panel_width)
        
        if editing_offset != -1 and clicked_byte_offset != editing_offset:
            editing_offset = -1
            edit_buffer = ""

        # Only set selection if the click is in the hex view area
        if clicked_byte_offset != -1:
            selection_start = clicked_byte_offset
            selection_end = selection_start
        
        current_time = get_time()
        if (current_time - last_click_time) < DOUBLE_CLICK_INTERVAL and clicked_byte_offset != -1:
            for entry in stored_entries:
                entry['is_editing'] = False
            
            editing_offset = clicked_byte_offset
            edit_buffer = ""
        last_click_time = current_time

    elif is_mouse_button_down(MouseButton.MOUSE_BUTTON_LEFT) and not dragging_scrollbar:
        new_selection_end = get_byte_offset_from_mouse(viewer_panel_width)
        if new_selection_end != -1:
            selection_end = new_selection_end


    # --- Keyboard Navigation & Interaction (WASD/EQ) ---
    if editing_offset == -1 and selection_end != -1 and not active_input:
        moved = False
        new_selection = selection_end

        if is_key_pressed_with_repeat(KeyboardKey.KEY_D) and not is_editing_stored_entry:
            new_selection += 1
            moved = True
        if is_key_pressed_with_repeat(KeyboardKey.KEY_A) and not is_editing_stored_entry:
            new_selection -= 1
            moved = True
        if is_key_pressed_with_repeat(KeyboardKey.KEY_S) and not is_editing_stored_entry:
            new_selection += bytes_per_row
            moved = True
        if is_key_pressed_with_repeat(KeyboardKey.KEY_W) and not is_editing_stored_entry:
            new_selection -= bytes_per_row
            moved = True

        if moved:
            selection_end = max(0, min(new_selection, len(memory_data) - 1))
            selection_start = selection_end

            # Auto-scroll logic
            selected_row = selection_end // bytes_per_row
            top_visible_row = int(memory_scroll_offset / item_height)
            bottom_visible_row = top_visible_row + visible_rows - 1

            if selected_row < top_visible_row:
                memory_scroll_offset = float(selected_row * item_height)
            elif selected_row > bottom_visible_row:
                memory_scroll_offset = float((selected_row - visible_rows + 1) * item_height)
            
            memory_scroll_offset = max(0, min(memory_scroll_offset, scroll_max))

        # --- Actions for the selected cell ---
        if is_key_pressed(KeyboardKey.KEY_Q) and not is_editing_stored_entry:
            editing_offset = selection_end
            edit_buffer = ""
            for entry in stored_entries: entry['is_editing'] = False
            
        if is_key_pressed(KeyboardKey.KEY_E) and not is_editing_stored_entry:
            address_to_store = get_true_address(selection_end)
            if not any(e['address'] == address_to_store for e in stored_entries):
                size_map = {"1 Byte": 1, "2 Bytes": 2, "4 Bytes": 4, "Float": 4, "Hex": 1}
                size_to_read = size_map.get(scan_data_type, 1)
                
                if selection_end + size_to_read <= len(memory_data):
                    value_bytes = memory_data[selection_end : selection_end + size_to_read]
                    stored_entries.append({
                        'address': address_to_store, 
                        'value': value_bytes, 'is_editing': False, 'edit_buffer': "",
                        'type': scan_data_type, 'is_frozen': False,
                        'is_big_endian': False, 
                        'description':"", 'is_editing_des': False, 'edit_buffer_des': ""
                    })
                    print(f"Stored address 0x{address_to_store:X}")
            else:
                print(f"Address 0x{address_to_store:X} is already stored.")

    # --- Handle input for Hex edit mode ---
    if editing_offset != -1:
        char_code = get_char_pressed()
        if char_code > 0:
            char = chr(char_code)
            if '0' <= char.lower() <= '9' or 'a' <= char.lower() <= 'f':
                if len(edit_buffer) < 2:
                    edit_buffer += char.upper()

        if is_key_pressed(KeyboardKey.KEY_BACKSPACE):
            edit_buffer = edit_buffer[:-1]
        
        if is_key_pressed(KeyboardKey.KEY_ESCAPE):
            editing_offset = -1; edit_buffer = ""
            
        if is_key_pressed(KeyboardKey.KEY_ENTER):
            if len(edit_buffer) > 0:
                write_to_memory(editing_offset, edit_buffer)
            editing_offset = -1; edit_buffer = ""
            
        next_offset = -1
        if is_key_pressed_with_repeat(KeyboardKey.KEY_RIGHT): next_offset = editing_offset + 1
        if is_key_pressed_with_repeat(KeyboardKey.KEY_LEFT): next_offset = editing_offset - 1
        if is_key_pressed_with_repeat(KeyboardKey.KEY_UP): next_offset = editing_offset - bytes_per_row
        if is_key_pressed_with_repeat(KeyboardKey.KEY_DOWN): next_offset = editing_offset + bytes_per_row
        
        if next_offset != -1:
            if len(edit_buffer) > 0:
                write_to_memory(editing_offset, edit_buffer)
            if 0 <= next_offset < len(memory_data):
                editing_offset = next_offset; edit_buffer = ""
            else:
                editing_offset = -1; edit_buffer = ""

    # --- 2. HANDLE ALL DRAWING ---
    draw_text_ex(font, f"Memory Viewer - PID: {selected_pid} : {selected_name}", (20, 20), 20, 1, header_color)
    draw_rectangle_rec(back_button_rect, header_color)
    draw_text_ex(font, "Back", (int(back_button_rect.x + 30), int(back_button_rect.y + 5)), 20, 1, WHITE)
    if not memory_data:
        draw_text_ex(font, "No memory data to display.", (20, 60), font_size, 1, text_color); return
    addr_col_width, hex_col_width = 220, 25
    ascii_col_start = addr_col_width + (bytes_per_row * hex_col_width) + 20
    path_col_start = ascii_col_start + (bytes_per_row * 10) + 30

    draw_text_ex(font, "Address", (20, TOP_HEIGHT_PX), font_size, 1, header_color)
    for i in range(bytes_per_row):
        draw_text_ex(font, f"{i:X}", (addr_col_width + i * hex_col_width, TOP_HEIGHT_PX), font_size, 1, header_color)
    draw_text_ex(font, "ASCII", (ascii_col_start, TOP_HEIGHT_PX), font_size, 1, header_color)
    draw_text_ex(font, "Path", (path_col_start, TOP_HEIGHT_PX), font_size, 1, header_color)
    
    start_row = int(memory_scroll_offset / item_height)
    end_row = start_row + visible_rows + 2
    y_offset = 0
    for row_index in range(start_row, end_row):
        offset = row_index * bytes_per_row
        if offset >= len(memory_data): break
        y = int(scrollbar_area_y + (row_index * item_height) - memory_scroll_offset + y_offset)
        
        current_region_info = next((r for r in reversed(region_boundaries) if offset >= r['offset']), None)
        if not current_region_info: continue
        
        r_start_offset, r_addr, r_size, r_path = current_region_info['offset'], current_region_info['addr'], current_region_info['size'], current_region_info['path']
        is_region_valid = current_region_info['is_valid'] # <-- NEW: Get validity status
        
        if offset > 0 and offset == r_start_offset:
            draw_text_ex(font, "--- Region Break ---", (20, y), font_size, 1, placeholder_color)
            for i in range(bytes_per_row): draw_text_ex(font, "XX", (addr_col_width + i * hex_col_width, y), font_size, 1, placeholder_color)
            draw_text_ex(font, "." * bytes_per_row, (ascii_col_start, y), font_size, 1, placeholder_color)
            y_offset += item_height
            y = int(scrollbar_area_y + (row_index * item_height) - memory_scroll_offset + y_offset)

        offset_in_region = offset - r_start_offset
        draw_text_ex(font, f"{r_addr + offset_in_region:016X}", (20, y), font_size, 1, text_color)
        
        ascii_chars = ""
        for col_index in range(bytes_per_row):
            x = addr_col_width + col_index * hex_col_width
            
            if not is_region_valid:
                draw_text_ex(font, "XX", (x, y), font_size, 1, placeholder_color)
                ascii_chars += "?"
                continue # Skip to the next byte column

            byte_offset = offset + col_index
            
            if byte_offset == editing_offset:
                draw_rectangle(x - 4, y - 2, hex_col_width, item_height, selection_color)
                draw_text_ex(font, edit_buffer, (x, y), font_size, 1, text_color)
                if (int(get_time() * 2) % 2) == 0:
                    cursor_x = x + measure_text_ex(font, edit_buffer, font_size, 1).x
                    draw_rectangle(int(cursor_x + 2), y, 2, item_height - 4, text_color)
            
            elif (offset_in_region + col_index) >= r_size:
                draw_text_ex(font, "XX", (x, y), font_size, 1, placeholder_color)
                ascii_chars += "."
            else:
                current_byte_address = r_addr + offset_in_region + col_index
                
                if selection_start != -1 and selection_end != -1 and min(selection_start, selection_end) <= byte_offset <= max(selection_start, selection_end):
                    draw_rectangle(x - 4, y - 2, hex_col_width, item_height, selection_color)
                
                if current_byte_address in changed_bytes:
                    draw_rectangle(x - 4, y - 2, hex_col_width, item_height, RED)
                
                byte_val = memory_data[byte_offset]
                draw_text_ex(font, f"{byte_val:02X}", (x, y), font_size, 1, text_color)
                ascii_chars += chr(byte_val) if 32 <= byte_val <= 126 else "."
        draw_text_ex(font, ascii_chars, (ascii_col_start, y), font_size, 1, text_color)

        path_to_draw = os.path.basename(r_path)
        draw_text_ex(font, path_to_draw, (path_col_start, y), font_size, 1, text_color)

    scrollbar_track_rect = Rectangle(float(viewer_panel_width - 25), float(scrollbar_area_y), 15.0, float(scrollbar_area_height))
    scroll_bar_draw(total_rows, visible_rows, scrollbar_track_rect, scrollbar_handle_rect)

    # --- Draw Scan Panel ---
    draw_text_ex(font, "Value Scanner", (scanner_panel_x, 20), 20, 1, header_color)
    draw_rectangle_rec(scan_input_box, WHITE)
    draw_rectangle_lines_ex(scan_input_box, 1, BLUE if active_input else header_color)
    
    draw_text_ex(font, scan_value_text, (int(scan_input_box.x + 5), int(scan_input_box.y + 5)), font_size, 1, text_color)
    if active_input and (int(get_time() * 2) % 2) == 0:
        draw_text_ex(font, "|", (int(scan_input_box.x + 5 + measure_text_ex(font, scan_value_text, font_size, 1).x), int(scan_input_box.y + 5)), font_size, 1, text_color)

    draw_rectangle_rec(byte1_btn, BLUE if scan_data_type == "1 Byte" else LIGHTGRAY)
    draw_text("1B", int(byte1_btn.x + btn_width/2 - 10), int(byte1_btn.y + 5), 20, WHITE)
    
    draw_rectangle_rec(byte2_btn, BLUE if scan_data_type == "2 Bytes" else LIGHTGRAY)
    draw_text("2B", int(byte2_btn.x + btn_width/2 - 10), int(byte2_btn.y + 5), 20, WHITE)

    draw_rectangle_rec(byte4_btn, BLUE if scan_data_type == "4 Bytes" else LIGHTGRAY)
    draw_text("4B", int(byte4_btn.x + btn_width/2 - 10), int(byte4_btn.y + 5), 20, WHITE)

    draw_rectangle_rec(float_btn, BLUE if scan_data_type == "Float" else LIGHTGRAY)
    draw_text("F", int(float_btn.x + btn_width/2 - 5), int(float_btn.y + 5), 20, WHITE)

    draw_rectangle_rec(hex_btn, BLUE if scan_data_type == "Hex" else LIGHTGRAY)
    draw_text("Hex", int(hex_btn.x + btn_width/2 - 15), int(hex_btn.y + 5), 20, WHITE)

    draw_rectangle_rec(ascii_btn, BLUE if scan_data_type == "ASCII" else LIGHTGRAY)
    draw_text("ASCII", int(ascii_btn.x + btn_width/2 - 20), int(ascii_btn.y + 5), 20, WHITE)

    # New: Draw Comparison Buttons
    draw_rectangle_rec(equal_btn, BLUE if scan_comparison_type == "==" else LIGHTGRAY)
    draw_text("==", int(equal_btn.x + comp_btn_width/2 - 10), int(equal_btn.y + 5), 20, WHITE)
    draw_rectangle_rec(not_equal_btn, BLUE if scan_comparison_type == "!=" else LIGHTGRAY)
    draw_text("!=", int(not_equal_btn.x + comp_btn_width/2 - 10), int(not_equal_btn.y + 5), 20, WHITE)
    draw_rectangle_rec(greater_btn, BLUE if scan_comparison_type == ">" else LIGHTGRAY)
    draw_text(">", int(greater_btn.x + comp_btn_width/2 - 5), int(greater_btn.y + 5), 20, WHITE)
    draw_rectangle_rec(less_btn, BLUE if scan_comparison_type == "<" else LIGHTGRAY)
    draw_text("<", int(less_btn.x + comp_btn_width/2 - 5), int(less_btn.y + 5), 20, WHITE)

    
    draw_rectangle_rec(first_scan_button, header_color)
    draw_text("First Scan", int(first_scan_button.x + 50), int(first_scan_button.y + 5), 20, WHITE)
    draw_rectangle_rec(next_scan_button, header_color)
    draw_text("Next Scan", int(next_scan_button.x + 50), int(next_scan_button.y + 5), 20, WHITE)
    draw_rectangle_rec(store_button, header_color)
    draw_text("Store", int(store_button.x + 50), int(store_button.y + 5), 20, WHITE)
    
    # --- Results Panel Logic with Virtual Scrolling ---
    results_panel_height = screen_height - results_panel_y - 20
    results_area_height = results_panel_height - results_header_height
    results_area = Rectangle(scanner_panel_x, results_panel_y + results_header_height, scanner_panel_width - 20, results_area_height)

    # Handle mouse wheel scrolling for results from scan
    if check_collision_point_rec(mouse_pos, results_area):
        mouse_wheel = get_mouse_wheel_move()
        if (get_mouse_x() > 1130):
            scan_results_scroll_offset -= mouse_wheel * item_height

    # Calculate virtualization parameters
    total_results = len(scan_results)
    visible_results = int(results_area_height / item_height)
    max_results_scroll = max(0, (total_results * item_height) - results_area_height)
    scan_results_scroll_offset = max(0, min(scan_results_scroll_offset, max_results_scroll))

    start_index = int(scan_results_scroll_offset / item_height)
    end_index = min(total_results, start_index + visible_results + 2) # +2 for smooth scrolling

    # Handle single-click to jump
    if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT) and check_collision_point_rec(mouse_pos, results_area):
        mouse_y = get_mouse_y()
        # Adjust clicked_index calculation for virtualization
        clicked_index = start_index + int((mouse_y - results_area.y) / item_height)

        if 0 <= clicked_index < total_results:
            target_address = scan_results[clicked_index]
            stitched_offset = get_offset_from_true_address(target_address)

            if stitched_offset != -1:
                target_row = stitched_offset // bytes_per_row
                memory_scroll_offset = float(target_row * item_height)
                selection_start = stitched_offset
                selection_end = stitched_offset
                memory_scroll_offset = max(0, min(memory_scroll_offset, scroll_max))

    # Draw Header
    # draw_text_ex(font, f"{total_results} results found", (scanner_panel_x, results_panel_y), font_size, 1, header_color)
    draw_text_ex(font, scanner_status_message, (scanner_panel_x, results_panel_y), font_size, 1, header_color)
    
    # Draw Results (virtualized)
    begin_scissor_mode(int(results_area.x), int(results_area.y), int(results_area.width), int(results_area.height))
    if total_results > 5000:
        draw_text_ex(font, "Too many results", (scanner_panel_x + 5, results_area.y + 5), font_size, 1, text_color)
        draw_text_ex(font, " to display.", (scanner_panel_x + 5, results_area.y + 15), font_size, 1, text_color)
    else:
        for i in range(start_index, end_index):
            addr = scan_results[i]
            y = int(results_area.y + (i * item_height) - scan_results_scroll_offset)
            
            # Highlight if the result address is the currently selected one in the main view
            offset_in_stitch = get_offset_from_true_address(addr)
            text_col = text_color
            if offset_in_stitch != -1 and selection_start != -1 and selection_end != -1:
                 if min(selection_start, selection_end) <= offset_in_stitch < max(selection_start, selection_end) + 1:
                    text_col = BLUE # Use a different color to avoid confusion with main selection
            
            draw_text_ex(font, f"0x{addr:016X}", (scanner_panel_x + 5, y), font_size, 1, text_col)
    end_scissor_mode()

    # Draw Scrollbar for results
    results_scrollbar_track = Rectangle(results_area.x + results_area.width - 15, results_area.y, 15, results_area.height)
    if total_results > visible_results:
        handle_height = max(20, results_area.height * visible_results / total_results)
        handle_y_max = results_area.height - handle_height
        handle_y = results_area.y + (scan_results_scroll_offset / max_results_scroll * handle_y_max if max_results_scroll > 0 else 0)
        results_scrollbar_handle = Rectangle(results_scrollbar_track.x, handle_y, 15, handle_height)
        
        draw_rectangle_rec(results_scrollbar_track, LIGHTGRAY)
        draw_rectangle_rec(results_scrollbar_handle, GRAY)

    draw_stored_entries_panel(20, viewer_height + 20, viewer_panel_width - 40, stored_panel_height, scroll_max)
    

    

def store_all_scan_results():
    global stored_entries, scan_results, scan_data_type
    if not scan_results:
        print("No results to store.")
        return

    stored_count = 0
    for address_to_store in scan_results:
        # Check for duplicates first
        is_duplicate = False
        for entry in stored_entries:
            if entry['address'] == address_to_store:
                is_duplicate = True
                break
        if is_duplicate:
            continue

        offset = get_offset_from_true_address(address_to_store)
        if offset == -1:
            print(f"Could not find offset for address {address_to_store:X}")
            continue

        # Determine the size of the data to read
        size_to_read = 1
        if "1" in scan_data_type: size_to_read = 1
        elif "2" in scan_data_type: size_to_read = 2
        elif "4" in scan_data_type: size_to_read = 4
        elif "Float" in scan_data_type: size_to_read = 4
        elif "ASCII" in scan_data_type: size_to_read = len(scan_value_text.encode('ascii'))
        
        value_bytes = memory_data[offset:offset+size_to_read]
        
        stored_entries.append({
            'address': address_to_store,
            'value': value_bytes,
            'type': scan_data_type,
            'is_frozen': False, # New: For locking the value
            'is_big_endian': False, # New: For endian swapping
            'description': "",
            'is_editing': False, # New: To control edit mode
            'edit_buffer': "", # New: To hold the value while editing
            'is_editing_des': False, # New: To control edit mode
            'edit_buffer_des': "" # New: To hold the value while editing
        })
        stored_count += 1

    print(f"Stored {stored_count} new entries. Total stored: {len(stored_entries)}")



def draw_stored_entries_panel(x, y, width, height, scroll_max):
    global stored_entries_scroll_offset, stored_entries, stored_entries_last_click_time, process_handle, font, memory_scroll_offset, selection_start, selection_end, bytes_per_row
    
    draw_text_ex(font, "Stored Entries", (x, y), 20, 1, header_color)
    
    # Header
    col1_x, col2_x, col3_x, col4_x, col5_x, col6_x, col7_x = x + 10, x + 160, x + 280, x + 360, x + 520, x + 600, x + width - 30
    draw_text_ex(font, "Address", (col1_x, y + 30), font_size, 1, text_color)
    draw_text_ex(font, "Value", (col2_x, y + 30), font_size, 1, text_color)
    draw_text_ex(font, "Type", (col3_x, y + 30), font_size, 1, text_color)
    draw_text_ex(font, "Description", (col4_x, y + 30), font_size, 1, text_color)
    draw_text_ex(font, "Endian", (col5_x, y + 30), font_size, 1, text_color)
    draw_text_ex(font, "Frozen", (col6_x, y + 30), font_size, 1, text_color)
    draw_line(int(x), int(y + 50), int(x + width), int(y + 50), header_color)

    # stored values content
    content_rect = Rectangle(x, y + 55, width, height - 55)
    begin_scissor_mode(int(content_rect.x), int(content_rect.y), int(content_rect.width), int(content_rect.height))

    if check_collision_point_rec(get_mouse_position(), content_rect):
        mouse_wheel = get_mouse_wheel_move()
        if (get_mouse_y() > 640 and get_mouse_x() < 1130):
            stored_entries_scroll_offset -= mouse_wheel * item_height
            max_scroll_local = max(0, len(stored_entries) * item_height - content_rect.height)
            stored_entries_scroll_offset = max(0, min(stored_entries_scroll_offset, max_scroll_local))

    # Helper function to get the display value as a string
    def get_display_value(entry):
        try:
            val_bytes = entry['value']
            if not val_bytes: return "N/A"
            
            # Determine endianness for multi-byte types
            endian_char = '>' if entry.get('is_big_endian', False) else '<'
            
            if entry['type'] == "Float" and len(val_bytes) >= 4: return f"{struct.unpack(endian_char + 'f', val_bytes)[0]:.3f}"
            if entry['type'] == "4 Bytes" and len(val_bytes) >= 4: return str(struct.unpack(endian_char + 'i', val_bytes)[0])
            if entry['type'] == "2 Bytes" and len(val_bytes) >= 2: return str(struct.unpack(endian_char + 'h', val_bytes)[0])
            
            # Types without endianness
            if entry['type'] == "1 Byte" and len(val_bytes) >= 1: return str(struct.unpack('<b', val_bytes)[0])
            if entry['type'] == "ASCII": return val_bytes.decode('ascii', errors='ignore')
            return val_bytes.hex().upper()
        except (struct.error, IndexError):
            return "Read Error"

    entries_to_remove = []
    for i, entry in enumerate(stored_entries):
        # if entry['is_editing']:
        if entry.get('is_editing', False) or entry.get('is_editing_des', False):
            key = get_char_pressed()
            while key > 0:
                if 32 <= key <= 126:
                    if entry.get('is_editing_des', False):
                        entry['edit_buffer_des'] += chr(key)
                    else:
                        entry['edit_buffer'] += chr(key)
                key = get_char_pressed()
            
            if is_key_pressed(KeyboardKey.KEY_BACKSPACE):
                if entry.get('is_editing_des', False):
                    entry['edit_buffer_des'] = entry['edit_buffer_des'][:-1]
                else:
                    entry['edit_buffer'] = entry['edit_buffer'][:-1]

            if is_key_pressed(KeyboardKey.KEY_ENTER) or is_key_pressed(KeyboardKey.KEY_ESCAPE):
                if is_key_pressed(KeyboardKey.KEY_ENTER):
                    if entry.get('is_editing_des'):
                        entry['description'] = entry['edit_buffer_des']
                    else:
                        try:
                            new_bytes = b''
                            buf = entry['edit_buffer']
                            endian_char = '>' if entry.get('is_big_endian', False) else '<'
                            
                            if entry['type'] == "Float":
                                new_bytes = struct.pack(endian_char + 'f', float(buf))
                            elif entry['type'] == "4 Bytes":
                                new_bytes = struct.pack(endian_char + 'i', int(buf))
                            elif entry['type'] == "2 Bytes":
                                new_bytes = struct.pack(endian_char + 'h', int(buf))
                            elif entry['type'] == "1 Byte":
                                new_bytes = struct.pack('<b', int(buf))
                            elif entry['type'] == "ASCII":
                                new_bytes = buf.encode('ascii')
                            else: # Assumes "Hex"
                                new_bytes = bytes.fromhex(buf)

                            win32process.WriteProcessMemory(process_handle.handle, entry['address'], new_bytes)
                            entry['value'] = bytearray(new_bytes)
                            print(f"Successfully wrote {buf} to 0x{entry['address']:X}")

                        except (ValueError, struct.error, pywintypes.error) as e:
                            print(f"Error applying edit for type {entry['type']}: {e}")
                    
                entry['is_editing'] = False
                entry['edit_buffer'] = ""
                entry['is_editing_des'] = False
                entry['edit_buffer_des'] = ""

    # Drawing and input detection loop
    for i, entry in enumerate(stored_entries):
        entry_y = int(content_rect.y + (i * item_height) - stored_entries_scroll_offset)
        if entry_y < content_rect.y - item_height or entry_y > content_rect.y + content_rect.height:
            continue

        # Define rectangles for each column
        address_rect = Rectangle(col1_x, float(entry_y), col2_x - col1_x - 10, float(item_height))
        value_rect = Rectangle(col2_x, float(entry_y), col3_x - col2_x - 10, float(item_height))
        type_rect = Rectangle(col3_x, float(entry_y), col4_x - col3_x - 10, float(item_height))
        description_rect = Rectangle(col4_x, float(entry_y), col5_x - col4_x - 10, float(item_height))
        endian_rect = Rectangle(col5_x, float(entry_y), col6_x - col5_x - 10, float(item_height))
        checkbox_rect = Rectangle(col6_x + 15, float(entry_y), float(item_height - 4), float(item_height - 4))
        close_button_rect = Rectangle(col7_x, float(entry_y), float(item_height - 4), float(item_height - 4))
        

        draw_text_ex(font, f"0x{entry['address']:X}", (col1_x, entry_y), font_size, 1, text_color)

        if entry['is_editing']:
            draw_rectangle_rec(value_rect, WHITE)
            draw_rectangle_lines_ex(value_rect, 1, BLUE)
            draw_text_ex(font, entry['edit_buffer'], (int(value_rect.x + 5), entry_y), font_size, 1, text_color)
            if (int(get_time() * 2) % 2) == 0:
                cursor_x = int(value_rect.x + 5 + measure_text_ex(font, entry['edit_buffer'], font_size, 1).x)
                draw_rectangle(cursor_x, entry_y, 2, item_height, text_color)
        else:
            display_value = get_display_value(entry)
            draw_text_ex(font, display_value, (col2_x + 5, entry_y), font_size, 1, text_color)
        
        if entry['is_editing_des']:
            draw_rectangle_rec(description_rect, WHITE)
            draw_rectangle_lines_ex(description_rect, 1, BLUE)
            draw_text_ex(font, entry.get('edit_buffer_des',''), (int(description_rect.x + 5), entry_y), font_size, 1, text_color)
            if (int(get_time() * 2) % 2) == 0:
                cursor_x = int(description_rect.x + 5 + measure_text_ex(font, entry['edit_buffer_des'], font_size, 1).x)
                draw_rectangle(cursor_x, entry_y, 2, item_height, text_color)
        else:
            display_value = entry.get('description', '')
            draw_text_ex(font, display_value, (col4_x + 5, entry_y), font_size, 1, text_color)



        draw_rectangle_lines_ex(type_rect, 1, DARKGRAY)
        draw_text_ex(font, entry['type'], (int(type_rect.x + 5), entry_y), font_size, 1, text_color)

        # Draw Endian Toggle
        is_endian_type = entry['type'] in ["2 Bytes", "4 Bytes", "Float"]
        if is_endian_type:
            draw_rectangle_lines_ex(endian_rect, 1, DARKGRAY)
            endian_text = "Big" if entry.get('is_big_endian', False) else "Little"
            draw_text_ex(font, endian_text, (int(endian_rect.x + 5), entry_y), font_size, 1, text_color)

        draw_rectangle_lines_ex(checkbox_rect, 2, text_color)
        if entry['is_frozen']:
            draw_rectangle(int(checkbox_rect.x + 4), int(checkbox_rect.y + 4), int(checkbox_rect.width - 8), int(checkbox_rect.height - 8), BLUE)
        
        # if entry['description']:
        #     draw_rectangle_rec(description_rect, WHITE)
        #     draw_rectangle_lines_ex(description_rect, 1, BLUE)
        #     draw_text_ex(font, entry['description'], (int(description_rect.x + 5), entry_y), font_size, 1, text_color)
        #     if (int(get_time() * 2) % 2) == 0:
        #         cursor_x = int(description_rect.x + 5 + measure_text_ex(font, entry['description'], font_size, 1).x)
        #         draw_rectangle(cursor_x, entry_y, 2, item_height, text_color)

        draw_rectangle_rec(close_button_rect, RED)
        draw_text("X", int(close_button_rect.x + 5), int(close_button_rect.y + 2), 15, WHITE)

        if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT):
            mouse_pos = get_mouse_position()
            current_time = get_time()

            if check_collision_point_rec(mouse_pos, address_rect):
                stitched_offset = get_offset_from_true_address(entry['address'])
                if stitched_offset != -1:
                    target_row = stitched_offset // bytes_per_row
                    memory_scroll_offset = float(target_row * item_height)
                    selection_start = stitched_offset
                    selection_end = stitched_offset
                    memory_scroll_offset = max(0, min(memory_scroll_offset, scroll_max))

            elif check_collision_point_rec(mouse_pos, value_rect):
                if (current_time - stored_entries_last_click_time) < DOUBLE_CLICK_INTERVAL:
                    global editing_offset, edit_buffer
                    editing_offset = -1
                    edit_buffer = ""
                    for e in stored_entries: e['is_editing'] = False
                    entry['is_editing'] = True
                    entry['edit_buffer'] = get_display_value(entry)
                stored_entries_last_click_time = current_time
                
            elif check_collision_point_rec(mouse_pos, description_rect):
                if (current_time - stored_entries_last_click_time) < DOUBLE_CLICK_INTERVAL:
                    editing_offset = -1
                    edit_buffer = ""
                    for e in stored_entries: e['is_editing_des'] = False
                    entry['is_editing_des'] = True
                    entry['edit_buffer_des'] = entry.get('description', '')
                stored_entries_last_click_time = current_time

            elif check_collision_point_rec(mouse_pos, checkbox_rect):
                entry['is_frozen'] = not entry['is_frozen']

            elif is_endian_type and check_collision_point_rec(mouse_pos, endian_rect):
                entry['is_big_endian'] = not entry.get('is_big_endian', False)
                entry['value'].reverse() # Reverse the bytearray in-place
            
            elif check_collision_point_rec(mouse_pos, type_rect):
                data_types_cycle = ["1 Byte", "2 Bytes", "4 Bytes", "Float", "Hex", "ASCII"]
                try:
                    current_index = data_types_cycle.index(entry['type'])
                    new_type = data_types_cycle[(current_index + 1) % len(data_types_cycle)]
                except ValueError:
                    new_type = data_types_cycle[0]
                entry['type'] = new_type

                size_map = {"1 Byte": 1, "2 Bytes": 2, "4 Bytes": 4, "Float": 4, "Hex": len(entry['value']), "ASCII": len(entry['value'])}
                new_size = size_map.get(new_type, 1)
                try:
                    new_value_bytes = win32process.ReadProcessMemory(process_handle.handle, entry['address'], new_size)
                    entry['value'] = bytearray(new_value_bytes)
                except pywintypes.error as e:
                    print(f"Could not re-read memory for type change: {e}")
            
            elif check_collision_point_rec(mouse_pos, close_button_rect):
                entries_to_remove.append(entry)

    if entries_to_remove:
        for entry in entries_to_remove:
            stored_entries.remove(entry)

    end_scissor_mode()
    
    # Draw Scrollbar for stored
    total_stored = len(stored_entries * item_height) - content_rect.height
    total_rows = len(stored_entries)
    visible_stored = int(content_rect.height / item_height)
    stored_scrollbar_track = Rectangle(content_rect.x+content_rect.width-15//4,content_rect.y, 15, content_rect.height)
    scroll_max = max(0, (total_rows * item_height) - content_rect.height)
    
    if total_stored > visible_stored:
        handle_height = max(20, content_rect.height * visible_stored / total_stored)
        handle_y_max = content_rect.height - handle_height
        handle_y = content_rect.y + (stored_entries_scroll_offset / scroll_max * handle_y_max if scroll_max > 0 else 0)
        stored_scrollbar_handle = Rectangle(stored_scrollbar_track.x, handle_y, 15, handle_height)
        
        draw_rectangle_rec(stored_scrollbar_track, LIGHTGRAY)
        draw_rectangle_rec(stored_scrollbar_handle, GRAY)
    
    

def update_frozen_values():
    """Continuously writes the stored value for any entry marked as 'frozen'."""
    if not process_handle:
        return

    for entry in stored_entries:
        if entry['is_frozen']:
            try:
                # THE FIX: Convert the mutable 'bytearray' to immutable 'bytes'
                bytes_to_write = bytes(entry['value'])
                win32process.WriteProcessMemory(process_handle.handle, entry['address'], bytes_to_write)
            except pywintypes.error as e:
                print(f"Failed to freeze value for address {entry['address']:X}. It might be protected. Error: {e}")
                # Optional: Unfreeze it so we don't spam errors
                entry['is_frozen'] = False



def handle_navigation_input(scroll_offset, item_height, view_height, boundaries, bytes_per_row, scroll_max):
    """Handles all keyboard navigation, with arrows jumping precisely between region breaks."""
    if not boundaries:
        return scroll_offset

    new_scroll_offset = scroll_offset
    
    # Current byte offset at the top of the view
    current_row = scroll_offset / item_height
    current_start_byte = int(current_row) * bytes_per_row

    # --- Page Up/Down for large jumps (hold-to-scroll) ---
    if is_key_pressed_with_repeat(KeyboardKey.KEY_PAGE_DOWN):
        jump_amount = (1000 / bytes_per_row) * item_height
        new_scroll_offset += jump_amount
        
    if is_key_pressed_with_repeat(KeyboardKey.KEY_PAGE_UP):
        jump_amount = (1000 / bytes_per_row) * item_height
        new_scroll_offset -= jump_amount
        

    # Down arrow: Jump to next region
    if is_key_pressed(KeyboardKey.KEY_DOWN):
        # CHANGE: Access the 'offset' key from the dictionary
        break_points = [b['offset'] for b in boundaries]
        next_bp = next((bp for bp in break_points if bp > current_start_byte), None)
        if next_bp is not None:
            target_row = next_bp // bytes_per_row
            new_scroll_offset = target_row * item_height
        else:
            new_scroll_offset = scroll_max

    # Up arrow: Jump to previous region
    if is_key_pressed(KeyboardKey.KEY_UP):
        # CHANGE: Access the 'offset' key from the dictionary
        break_points = [b['offset'] for b in boundaries]
        prev_bp = next((bp for bp in reversed(break_points) if bp < current_start_byte), None)
        if prev_bp is not None:
            target_row = prev_bp // bytes_per_row
            new_scroll_offset = target_row * item_height
        else:
            new_scroll_offset = 0

    # Clamp scroll offset
    new_scroll_offset = max(0, min(new_scroll_offset, scroll_max))
    return new_scroll_offset



def get_true_address(offset):
    # Find which region this offset falls into
    # CHANGE: Iterate over dictionaries instead of unpacking tuples
    for region in reversed(region_boundaries):
        if offset >= region['offset']:
            # Calculate the offset within this specific region
            offset_in_region = offset - region['offset']
            # Return the true memory address
            return region['addr'] + offset_in_region
            
    # Fallback to the first address if not found (should not happen)
    return region_boundaries[0]['addr'] + offset if region_boundaries else offset


def get_byte_offset_from_mouse(viewer_panel_width):
    mouse_x, mouse_y = get_mouse_x(), get_mouse_y()
    addr_col_width, hex_col_width, scrollbar_area_y = HEX_POS_X-5, 25, 85 # -5 from the pixel size of the letters +/-
    if mouse_y < scrollbar_area_y or mouse_x < addr_col_width: return -1
    row = int((mouse_y - scrollbar_area_y + memory_scroll_offset) / item_height)
    col = int((mouse_x - addr_col_width) / hex_col_width)
    return row * bytes_per_row + col if 0 <= col < bytes_per_row else -1

def copy_selection_to_clipboard():
    if selection_start == -1 or selection_end == -1: return
    start, end = min(selection_start, selection_end), max(selection_start, selection_end)
    selected_data = memory_data[start:end+1]
    hex_string = ' '.join(f'{byte:02X}' for byte in selected_data)
    pyperclip.copy(hex_string)
    print(f"Copied {len(selected_data)} bytes to clipboard.")


def unpack_value(data_bytes, data_type, is_big_endian=False):
    """
    Unpacks bytes into a number based on the data type. 
    Handles both little-endian and big-endian formats.
    Returns None if the type is not numeric or if an error occurs.
    """
    if not data_bytes:
        return None

    endian_char = '>' if is_big_endian else '<'
    
    try:
        if data_type == "Float":
            return struct.unpack(endian_char + 'f', data_bytes)[0]
        elif data_type == "4 Bytes":
            # Use 'i' for signed, 'I' for unsigned. 'i' is more common.
            return struct.unpack(endian_char + 'i', data_bytes)[0]
        elif data_type == "2 Bytes":
            return struct.unpack(endian_char + 'h', data_bytes)[0]
        elif data_type == "1 Byte":
            return struct.unpack(endian_char + 'b', data_bytes)[0]
        return None  # Type is not numeric (e.g., Hex, ASCII)
    except (struct.error, IndexError):
        return None
    
    

def perform_scan(first_scan=True):
    """
    Performs an efficient memory scan for both known and unknown values,
    supporting multiple comparison types.
    """
    global scan_results, scan_value_text, previous_scan_memory_data, scan_comparison_type, scan_data_type, scanner_status_message

    print(f"Performing scan (first: {first_scan}), value: '{scan_value_text}', type: {scan_data_type}, comparison: {scan_comparison_type}")
    text_to_scan = scan_value_text.strip()

    # --- 1. Handle scans that COMPARE memory (no value given) ---
    if not text_to_scan:
        if first_scan:
            scan_results = []
            previous_scan_memory_data = reread_memory_data()
            if previous_scan_memory_data:
                size_in_bytes = len(previous_scan_memory_data)
                scanner_status_message = f"Snapshot: {size_in_bytes / 1024 / 1024:.2f} MB"
                print("✅ Initial memory snapshot taken. Perform an action and run 'Next Scan'.")
            else:
                scanner_status_message = "Error: Snapshot failed"
            return

        latest_memory_data = reread_memory_data()
        if not previous_scan_memory_data or not latest_memory_data:
            scanner_status_message = "Error: No snapshot"
            return

        new_results_set = set()
        size_map = {"1 Byte": 1, "2 Bytes": 2, "4 Bytes": 4, "Float": 4}
        value_size = size_map.get(scan_data_type)

        if value_size is None:
            scanner_status_message = f"Error: Non-numeric type"
            print(f"❌ Error: Cannot perform comparison scan with non-numeric type '{scan_data_type}'.")
            return

        # --- EFFICIENT COMPARISON LOGIC ---
        
        # If scan_results is empty, this is the first comparison.
        # We must iterate through the memory BUFFERS directly.
        if not scan_results:
            print("Performing first comparison scan on memory buffers...")
            if len(previous_scan_memory_data) != len(latest_memory_data):
                scanner_status_message = "Error: Memory layout changed"
                print("❌ Error: Memory layout changed between scans. Please start a new scan.")
                return

            # Iterate through the memory buffers with a step equal to the data type size
            for offset in range(0, len(latest_memory_data) - value_size + 1, value_size):
                current_bytes = latest_memory_data[offset : offset + value_size]
                previous_bytes = previous_scan_memory_data[offset : offset + value_size]

                # Your existing comparison logic is perfect here
                match = False
                if scan_comparison_type in (">", "<"):
                    current_val, previous_val = unpack_value(current_bytes, scan_data_type), unpack_value(previous_bytes, scan_data_type)
                    if current_val is not None and previous_val is not None:
                        if scan_comparison_type == ">" and current_val > previous_val: match = True
                        elif scan_comparison_type == "<" and current_val < previous_val: match = True
                elif scan_comparison_type == "!=" and current_bytes != previous_bytes: match = True
                elif scan_comparison_type == "==" and current_bytes == previous_bytes: match = True
                
                if match:
                    # Find the true address only for the bytes that match
                    true_address = get_true_address(offset)
                    if true_address != -1:
                        new_results_set.add(true_address)

        # If scan_results is NOT empty, we filter the existing (small) list. This is always fast.
        else:
            print(f"Filtering {len(scan_results)} existing results...")
            for address in scan_results:
                offset = get_offset_from_true_address(address)
                if offset == -1 or offset + value_size > len(latest_memory_data): continue
                
                current_bytes = latest_memory_data[offset : offset + value_size]
                previous_bytes = previous_scan_memory_data[offset : offset + value_size]
                
                match = False
                if scan_comparison_type in (">", "<"):
                    current_val, previous_val = unpack_value(current_bytes, scan_data_type), unpack_value(previous_bytes, scan_data_type)
                    if current_val is not None and previous_val is not None:
                        if scan_comparison_type == ">" and current_val > previous_val: match = True
                        elif scan_comparison_type == "<" and current_val < previous_val: match = True
                elif scan_comparison_type == "!=" and current_bytes != previous_bytes: match = True
                elif scan_comparison_type == "==" and current_bytes == previous_bytes: match = True

                if match:
                    new_results_set.add(address)

        scan_results = sorted(list(new_results_set))
        previous_scan_memory_data = latest_memory_data
        scanner_status_message = f"{len(scan_results)} results found"
        return

    # --- 2. Handle scans for a KNOWN value (this part is unchanged) ---
    try:
        little_endian_bytes = b''
        if scan_data_type == "Float": little_endian_bytes = struct.pack('<f', float(text_to_scan))
        elif scan_data_type == "4 Bytes": little_endian_bytes = struct.pack('<i', int(text_to_scan, 0))
        elif scan_data_type == "2 Bytes": little_endian_bytes = struct.pack('<h', int(text_to_scan, 0))
        elif scan_data_type == "1 Byte": little_endian_bytes = struct.pack('<b', int(text_to_scan, 0))
        elif scan_data_type == "Hex": little_endian_bytes = bytes.fromhex(text_to_scan.replace(" ", ""))
        elif scan_data_type == "ASCII": little_endian_bytes = text_to_scan.encode('ascii')

        if not little_endian_bytes: return

        new_results_set, target_memory = set(), reread_memory_data()
        if not target_memory: return
        
        if first_scan:
            position = 0
            while True:
                found_pos = target_memory.find(little_endian_bytes, position)
                if found_pos == -1: break
                new_results_set.add(get_true_address(found_pos))
                position = found_pos + 1
        else:
             for address in scan_results:
                offset = get_offset_from_true_address(address)
                if offset != -1 and target_memory[offset:offset+len(little_endian_bytes)] == little_endian_bytes:
                    new_results_set.add(address)

        scan_results = sorted(list(new_results_set))
        scanner_status_message = f"{len(scan_results)} results found"

    except (ValueError, struct.error) as e:
        scanner_status_message = "Error: Invalid value"
    except Exception as e:
        scanner_status_message = "Error: Scan failed"
        
        
        

def scroll_bar_logic(memory_scroll_offset, dragging_scrollbar, total_rows, visible_rows, item_height, scrollbar_area_y, scrollbar_area_height, viewer_panel_width):
    """""
    Handles all input and calculations for the scrollbar.
    Returns the new scroll_offset, dragging state, and the handle's rectangle.
    """""
    # Calculate scroll dimensions
    scroll_max = (total_rows * item_height) - scrollbar_area_height
    scroll_max = max(0, scroll_max)

    # Mouse wheel input for memory map
    mouse_wheel = get_mouse_wheel_move()
    if (get_mouse_y() < 640 and get_mouse_x() < 1130):
        memory_scroll_offset -= mouse_wheel * item_height

    # Calculate handle dimensions
    handle_height = 0
    scrollbar_handle_rect = Rectangle(0, 0, 0, 0)
    if total_rows > visible_rows:
        handle_height = max(20, scrollbar_area_height * visible_rows / total_rows)
        handle_y_max = scrollbar_area_height - handle_height
        
        # Dragging logic
        handle_y = scrollbar_area_y + (memory_scroll_offset / scroll_max * handle_y_max if scroll_max > 0 else 0)
        scrollbar_handle_rect = Rectangle(float(viewer_panel_width - 25), float(handle_y), 15.0, float(handle_height))
        
        if is_mouse_button_pressed(MouseButton.MOUSE_BUTTON_LEFT) and check_collision_point_rec(get_mouse_position(), scrollbar_handle_rect):
            dragging_scrollbar = True
        
        if dragging_scrollbar:
            if is_mouse_button_released(MouseButton.MOUSE_BUTTON_LEFT):
                dragging_scrollbar = False
            else:
                mouse_dy = get_mouse_delta().y
                scroll_ratio = scroll_max / handle_y_max if handle_y_max > 0 else 0
                memory_scroll_offset += mouse_dy * scroll_ratio

    # Clamp final scroll offset
    memory_scroll_offset = max(0, min(memory_scroll_offset, scroll_max))
    
    return memory_scroll_offset, dragging_scrollbar, scrollbar_handle_rect

def scroll_bar_draw(total_rows, visible_rows, scrollbar_track_rect, scrollbar_handle_rect):
    """Draws the scrollbar track and handle if needed."""
    if total_rows > visible_rows:
        draw_rectangle_rec(scrollbar_track_rect, LIGHTGRAY)
        draw_rectangle_rec(scrollbar_handle_rect, GRAY)       
            

def draw_cursor_pos():
    x,y = get_mouse_position().x, get_mouse_position().y
    draw_text_ex(font, f"({x},{y})",(screen_width-300,10), 24,3,BLACK)          

def main():
    init_window(screen_width, screen_height, "Python Memory Viewer")
    set_target_fps(60)
    global font
    font = get_font_default()
    refresh_process_list()

    while not window_should_close():
        begin_drawing()
        clear_background(background_color)
        draw_cursor_pos()

        if app_state == "process_list":
            draw_process_list_screen()
        elif app_state == "memory_view":
            update_frozen_values() # Keep frozen values locked
            draw_memory_viewer_screen()

        end_drawing()

    # --- FINAL CLEANUP ---
    print("Window is closing, stopping background thread...")
    stop_thread_event.set()
    if memory_update_thread is not None and memory_update_thread.is_alive():
        memory_update_thread.join(timeout=1.0)

    if process_handle:
        win32api.CloseHandle(process_handle)
    close_window()

if __name__ == '__main__':
    main()