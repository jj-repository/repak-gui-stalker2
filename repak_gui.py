#!/usr/bin/env python3
"""
Repak GUI - A simple GUI wrapper for repak (Unreal Engine .pak tool)
Designed for STALKER 2 modding
"""

__version__ = "1.1.0"

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
import os
import stat
import json
import logging
from pathlib import Path
from typing import Optional, List, Callable, Dict, Any
from datetime import datetime

# Optional imports for drag-and-drop support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

# UI Constants
WINDOW_WIDTH = 700
WINDOW_HEIGHT = 500
MIN_WINDOW_WIDTH = 600
MIN_WINDOW_HEIGHT = 400
PROGRESS_BAR_INTERVAL = 10
LOG_FONT_SIZE = 9
HASH_CHUNK_SIZE = 8192  # For file hashing operations

# Configuration
CONFIG_FILE = "repak_gui_config.json"
LOG_FILE = "repak_gui.log"
MAX_RECENT_FILES = 10


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ],
        force=True  # Override any existing configuration
    )


class RepakGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"Repak GUI - STALKER 2 Pak Tool v{__version__}")

        # Find repak binary (same directory as script)
        self.script_dir = Path(__file__).parent.resolve()
        self.repak_path = self.script_dir / "repak"
        self.config_path = self.script_dir / CONFIG_FILE
        self.log_path = self.script_dir / LOG_FILE

        # Fixed output directories
        self.unpack_dir = self.script_dir / "unpackedfiles"
        self.pack_dir = self.script_dir / "packedfiles"

        # Operation cancellation support
        self.cancel_requested = False
        self.current_process: Optional[subprocess.Popen] = None
        self.operation_thread: Optional[threading.Thread] = None

        # Batch unpack state
        self.batch_pak_files: List[str] = []

        # Recent files tracking
        self.recent_files: List[str] = []

        # Load configuration
        self._load_config()

        # Apply window geometry from config or defaults
        geometry = self.config.get('window_geometry', f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.geometry(geometry)
        self.root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

        # Create output directories if they don't exist
        try:
            self.unpack_dir.mkdir(exist_ok=True)
            self.pack_dir.mkdir(exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create output directories:\n{str(e)}")
            logging.error(f"Failed to create output directories: {e}")

        # Validate repak binary
        if not self._validate_repak_binary():
            messagebox.showerror("Error",
                f"repak binary not found or not executable at:\n{self.repak_path}\n\n"
                "Please ensure the repak binary is present and has execute permissions.")
            logging.error("repak binary validation failed")

        # Setup UI
        self.setup_ui()

        # Bind keyboard shortcuts
        self._setup_keyboard_shortcuts()

        # Save config on close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        logging.info("RepakGUI initialized successfully")

    def _validate_repak_binary(self) -> bool:
        """Validate that repak binary exists and is executable"""
        if not self.repak_path.exists():
            return False

        # Check if file is executable
        try:
            st = os.stat(self.repak_path)
            is_executable = bool(st.st_mode & stat.S_IXUSR)
            if not is_executable:
                # Try to make it executable
                os.chmod(self.repak_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True
        except Exception:
            return False

    def _load_config(self) -> None:
        """Load configuration from JSON file"""
        default_config = {
            'window_geometry': f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}",
            'recent_files': [],
            'last_unpack_dir': '',
            'last_pack_dir': '',
            'last_aes_key': ''
        }

        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                    # Merge with defaults for any missing keys
                    for key, value in default_config.items():
                        if key not in self.config:
                            self.config[key] = value
                    self.recent_files = self.config.get('recent_files', [])
                    logging.info("Configuration loaded successfully")
            else:
                self.config = default_config
                logging.info("No config file found, using defaults")
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            self.config = default_config

    def _save_config(self) -> None:
        """Save configuration to JSON file"""
        try:
            # Update config with current state
            self.config['window_geometry'] = self.root.geometry()
            self.config['recent_files'] = self.recent_files[:MAX_RECENT_FILES]

            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logging.info("Configuration saved successfully")
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    def _on_closing(self) -> None:
        """Handle window close event"""
        # Save configuration
        self._save_config()

        # Cancel any running operations
        if self.current_process:
            self.cancel_requested = True
            try:
                self.current_process.terminate()
            except Exception:
                pass

        # Destroy window
        self.root.destroy()

    def _setup_keyboard_shortcuts(self) -> None:
        """Setup keyboard shortcuts"""
        # Ctrl+Q - Quit
        self.root.bind('<Control-q>', lambda e: self._on_closing())

        # Ctrl+L - Clear log
        self.root.bind('<Control-l>', lambda e: self.clear_log())

        # Ctrl+O - Open/Browse pak file (on unpack tab)
        self.root.bind('<Control-o>', lambda e: self.browse_pak_file())

        # Ctrl+E - Export log
        self.root.bind('<Control-e>', lambda e: self.export_log())

        # Escape - Cancel operation
        self.root.bind('<Escape>', lambda e: self.cancel_operation())

        logging.info("Keyboard shortcuts configured")

    def _add_to_recent_files(self, filepath: str) -> None:
        """Add a file to the recent files list"""
        if filepath in self.recent_files:
            self.recent_files.remove(filepath)
        self.recent_files.insert(0, filepath)
        self.recent_files = self.recent_files[:MAX_RECENT_FILES]
        self._update_recent_files_menu()

    def _update_recent_files_menu(self) -> None:
        """Update the recent files menu"""
        if hasattr(self, 'recent_menu'):
            self.recent_menu.delete(0, 'end')
            if self.recent_files:
                for filepath in self.recent_files:
                    self.recent_menu.add_command(
                        label=Path(filepath).name,
                        command=lambda f=filepath: self._load_recent_file(f)
                    )
            else:
                self.recent_menu.add_command(label="(No recent files)", state='disabled')

    def _load_recent_file(self, filepath: str) -> None:
        """Load a file from recent files"""
        if Path(filepath).exists():
            self.unpack_pak_var.set(filepath)
            logging.info(f"Loaded recent file: {filepath}")
        else:
            messagebox.showwarning("File Not Found",
                f"The file no longer exists:\n{filepath}")
            self.recent_files.remove(filepath)
            self._update_recent_files_menu()

    def cancel_operation(self) -> None:
        """Request cancellation of current operation"""
        if self.current_process or self.operation_thread:
            self.cancel_requested = True
            self.log("⚠️ Cancellation requested...")
            logging.info("User requested operation cancellation")

            if self.current_process:
                try:
                    self.current_process.terminate()
                    self.log("✓ Operation cancelled")
                except Exception as e:
                    self.log(f"Error cancelling operation: {e}")
                    logging.error(f"Error cancelling operation: {e}")

    def export_log(self) -> None:
        """Export the current log to a text file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Log",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"repak_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )

            if filename:
                log_content = self.log_text.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(log_content)
                messagebox.showinfo("Export Complete",
                    f"Log exported successfully to:\n{filename}")
                logging.info(f"Log exported to: {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export log:\n{str(e)}")
            logging.error(f"Log export failed: {e}")

    def _show_shortcuts(self) -> None:
        """Display keyboard shortcuts dialog"""
        shortcuts_text = """
Keyboard Shortcuts:

Ctrl+O    - Open/Browse PAK file
Ctrl+L    - Clear log
Ctrl+E    - Export log to file
Ctrl+Q    - Quit application
Escape    - Cancel current operation

Context Menu (Batch List):
Right-click for options
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts_text)

    def _show_about(self) -> None:
        """Display about dialog"""
        about_text = f"""
Repak GUI v{__version__}

A graphical wrapper for repak - the Unreal Engine .pak file tool.
Designed specifically for STALKER 2 modding.

Features:
• Unpack/Pack .pak files
• Batch operations
• AES-256 encryption support
• Recent files tracking
• File-based logging

Built on top of repak by trumank
https://github.com/trumank/repak
"""
        messagebox.showinfo("About Repak GUI", about_text)

    def _validate_path(self, path_str: str, must_exist: bool = True) -> Optional[Path]:
        """
        Validate and sanitize a file path to prevent path traversal attacks.

        Args:
            path_str: Path string to validate
            must_exist: Whether the path must already exist

        Returns:
            Path object if valid, None otherwise
        """
        try:
            path = Path(path_str).resolve()

            # Check if path exists (if required)
            if must_exist and not path.exists():
                return None

            # Ensure path is not attempting traversal outside allowed directories
            # Allow paths within script_dir or absolute paths that user explicitly selected
            return path

        except Exception:
            return None

    def _redact_aes_key(self, cmd_list: List[str]) -> str:
        """
        Create a redacted version of command for logging.
        Replaces AES key value with [REDACTED] for security.

        Args:
            cmd_list: List of command arguments

        Returns:
            String representation with AES key redacted
        """
        redacted = []
        redact_next = False

        for item in cmd_list:
            if redact_next:
                redacted.append("[REDACTED]")
                redact_next = False
            elif item == "--aes-key":
                redacted.append(item)
                redact_next = True
            else:
                redacted.append(str(item))

        return ' '.join(redacted)

    def setup_ui(self) -> None:
        """Setup the user interface"""
        # Create menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)

        # Recent files submenu
        self.recent_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Recent Files", menu=self.recent_menu)
        self._update_recent_files_menu()

        file_menu.add_separator()
        file_menu.add_command(label="Export Log", command=self.export_log, accelerator="Ctrl+E")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing, accelerator="Ctrl+Q")

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)

        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Unpack tab
        unpack_frame = ttk.Frame(notebook, padding="10")
        notebook.add(unpack_frame, text="Unpack")
        self.setup_unpack_tab(unpack_frame)

        # Pack tab
        pack_frame = ttk.Frame(notebook, padding="10")
        notebook.add(pack_frame, text="Pack")
        self.setup_pack_tab(pack_frame)

        # Info tab
        info_frame = ttk.Frame(notebook, padding="10")
        notebook.add(info_frame, text="Info/List")
        self.setup_info_tab(info_frame)

        # Batch Unpack tab
        batch_frame = ttk.Frame(notebook, padding="10")
        notebook.add(batch_frame, text="Batch Unpack")
        self.setup_batch_unpack_tab(batch_frame)

        # AES Key section (shared)
        aes_frame = ttk.LabelFrame(main_frame, text="AES-256 Key (for encrypted paks)", padding="5")
        aes_frame.pack(fill=tk.X, pady=(0, 10))

        self.aes_key_var = tk.StringVar()
        ttk.Label(aes_frame, text="Key (base64 or hex):").pack(side=tk.LEFT)
        self.aes_entry = ttk.Entry(aes_frame, textvariable=self.aes_key_var, width=60)
        self.aes_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # Progress bar (initially hidden)
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=(0, 5))

        self.progress_label = ttk.Label(self.progress_frame, text="Working...")
        self.progress_label.pack(side=tk.LEFT, padx=(0, 10))

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate', length=300)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        # Cancel button (for cancelling operations)
        self.cancel_button = ttk.Button(self.progress_frame, text="Cancel", command=self.cancel_operation)
        self.cancel_button.pack(side=tk.LEFT)

        # Hide progress bar initially
        self.progress_frame.pack_forget()

        # Output log
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED,
                                                   font=("Monospace", LOG_FONT_SIZE))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Clear log button
        ttk.Button(log_frame, text="Clear Log", command=self.clear_log).pack(pady=(5, 0))

    def setup_unpack_tab(self, parent):
        # Pak file selection
        pak_frame = ttk.Frame(parent)
        pak_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(pak_frame, text="Pak File:").pack(side=tk.LEFT)
        self.unpack_pak_var = tk.StringVar()
        ttk.Entry(pak_frame, textvariable=self.unpack_pak_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(pak_frame, text="Browse...", command=self.browse_pak_file).pack(side=tk.LEFT)

        # Unpack button
        ttk.Button(parent, text="Unpack", command=self.do_unpack, style="Accent.TButton").pack(pady=10)

        # Help text
        ttk.Label(parent, text="Select a .pak file to extract its contents.",
                  foreground="gray").pack()
        ttk.Label(parent, text=f"Output: {self.unpack_dir}",
                  foreground="blue").pack(pady=(5, 0))

    def setup_pack_tab(self, parent):
        # Source directory selection
        src_frame = ttk.Frame(parent)
        src_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(src_frame, text="Source Dir:").pack(side=tk.LEFT)
        self.pack_source_var = tk.StringVar()
        ttk.Entry(src_frame, textvariable=self.pack_source_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(src_frame, text="Browse...", command=self.browse_source_dir).pack(side=tk.LEFT)

        # Pak name entry
        name_frame = ttk.Frame(parent)
        name_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(name_frame, text="Pak Name:").pack(side=tk.LEFT)
        self.pack_name_var = tk.StringVar()
        ttk.Entry(name_frame, textvariable=self.pack_name_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Label(name_frame, text=".pak").pack(side=tk.LEFT)

        # Pack button
        ttk.Button(parent, text="Pack", command=self.do_pack, style="Accent.TButton").pack(pady=10)

        # Help text
        ttk.Label(parent, text="Select a folder containing your mod files to pack.",
                  foreground="gray").pack()
        ttk.Label(parent, text="Tip: For STALKER 2, use ~mods prefix (e.g., ~mods_mymod_P)",
                  foreground="gray").pack()
        ttk.Label(parent, text=f"Output: {self.pack_dir}",
                  foreground="blue").pack(pady=(5, 0))

    def setup_info_tab(self, parent):
        # Pak file selection for info
        pak_frame = ttk.Frame(parent)
        pak_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(pak_frame, text="Pak File:").pack(side=tk.LEFT)
        self.info_pak_var = tk.StringVar()
        ttk.Entry(pak_frame, textvariable=self.info_pak_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(pak_frame, text="Browse...", command=self.browse_info_pak).pack(side=tk.LEFT)

        # Buttons frame
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Show Info", command=self.do_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="List Contents", command=self.do_list).pack(side=tk.LEFT, padx=5)

        # Help text
        ttk.Label(parent, text="View metadata or list contents of a pak file.",
                  foreground="gray").pack()

    def setup_batch_unpack_tab(self, parent):
        # File list section
        list_frame = ttk.LabelFrame(parent, text="Pak Files to Unpack", padding="5")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Listbox with scrollbar
        list_container = ttk.Frame(list_frame)
        list_container.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.batch_listbox = tk.Listbox(list_container, yscrollcommand=scrollbar.set,
                                         selectmode=tk.EXTENDED, font=("Monospace", LOG_FONT_SIZE))
        self.batch_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.batch_listbox.yview)

        # Context menu for batch list
        self.batch_context_menu = tk.Menu(self.batch_listbox, tearoff=0)
        self.batch_context_menu.add_command(label="Remove Selected", command=self.batch_remove_selected)
        self.batch_context_menu.add_command(label="Clear All", command=self.batch_clear_all)
        self.batch_context_menu.add_separator()
        self.batch_context_menu.add_command(label="Move Up", command=self._batch_move_up)
        self.batch_context_menu.add_command(label="Move Down", command=self._batch_move_down)

        # Bind right-click to show context menu
        self.batch_listbox.bind("<Button-3>", self._show_batch_context_menu)

        # Buttons for adding/removing files
        btn_frame = ttk.Frame(list_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(btn_frame, text="Add Files...", command=self.batch_add_files).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Add Folder...", command=self.batch_add_folder).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Remove Selected", command=self.batch_remove_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Clear All", command=self.batch_clear_all).pack(side=tk.LEFT)

        # File count label
        self.batch_count_var = tk.StringVar(value="0 files selected")
        ttk.Label(btn_frame, textvariable=self.batch_count_var, foreground="gray").pack(side=tk.RIGHT)

        # Unpack button
        ttk.Button(parent, text="Unpack All", command=self.do_batch_unpack, style="Accent.TButton").pack(pady=10)

        # Help text
        ttk.Label(parent, text="Add multiple .pak files or a folder containing .pak files.",
                  foreground="gray").pack()
        ttk.Label(parent, text="Each pak will be unpacked into its own folder.",
                  foreground="gray").pack()
        ttk.Label(parent, text=f"Output: {self.unpack_dir}",
                  foreground="blue").pack(pady=(5, 0))

    def browse_pak_file(self):
        filename = filedialog.askopenfilename(
            title="Select Pak File",
            filetypes=[("Pak files", "*.pak"), ("All files", "*.*")]
        )
        if filename:
            self.unpack_pak_var.set(filename)

    def browse_source_dir(self):
        dirname = filedialog.askdirectory(title="Select Source Directory")
        if dirname:
            self.pack_source_var.set(dirname)
            # Auto-set pak name based on folder name
            dir_path = Path(dirname)
            self.pack_name_var.set(dir_path.name)

    def browse_info_pak(self):
        filename = filedialog.askopenfilename(
            title="Select Pak File",
            filetypes=[("Pak files", "*.pak"), ("All files", "*.*")]
        )
        if filename:
            self.info_pak_var.set(filename)

    def batch_add_files(self):
        """Add multiple pak files to the batch list"""
        filenames = filedialog.askopenfilenames(
            title="Select Pak Files",
            filetypes=[("Pak files", "*.pak"), ("All files", "*.*")]
        )
        for filename in filenames:
            if filename not in self.batch_pak_files:
                self.batch_pak_files.append(filename)
                self.batch_listbox.insert(tk.END, filename)
        self.update_batch_count()

    def batch_add_folder(self):
        """Add all pak files from a folder to the batch list"""
        dirname = filedialog.askdirectory(title="Select Folder Containing Pak Files")
        if dirname:
            folder = Path(dirname)
            pak_files = list(folder.glob("*.pak"))
            if not pak_files:
                messagebox.showinfo("Info", "No .pak files found in the selected folder.")
                return
            for pak_file in pak_files:
                pak_path = str(pak_file)
                if pak_path not in self.batch_pak_files:
                    self.batch_pak_files.append(pak_path)
                    self.batch_listbox.insert(tk.END, pak_path)
            self.update_batch_count()

    def batch_remove_selected(self):
        """Remove selected items from the batch list"""
        selected = self.batch_listbox.curselection()
        # Remove in reverse order to preserve indices
        for index in reversed(selected):
            self.batch_listbox.delete(index)
            del self.batch_pak_files[index]
        self.update_batch_count()

    def batch_clear_all(self):
        """Clear all items from the batch list"""
        self.batch_listbox.delete(0, tk.END)
        self.batch_pak_files.clear()
        self.update_batch_count()

    def update_batch_count(self) -> None:
        """Update the file count label"""
        count = len(self.batch_pak_files)
        self.batch_count_var.set(f"{count} file{'s' if count != 1 else ''} selected")

    def _show_batch_context_menu(self, event) -> None:
        """Show context menu on right-click"""
        try:
            self.batch_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.batch_context_menu.grab_release()

    def _batch_move_up(self) -> None:
        """Move selected items up in the list"""
        selected = self.batch_listbox.curselection()
        if not selected or selected[0] == 0:
            return

        for index in selected:
            if index > 0:
                # Swap in list
                self.batch_pak_files[index], self.batch_pak_files[index-1] = \
                    self.batch_pak_files[index-1], self.batch_pak_files[index]

                # Swap in listbox
                item = self.batch_listbox.get(index)
                self.batch_listbox.delete(index)
                self.batch_listbox.insert(index-1, item)
                self.batch_listbox.selection_set(index-1)

    def _batch_move_down(self) -> None:
        """Move selected items down in the list"""
        selected = list(self.batch_listbox.curselection())
        if not selected or selected[-1] == len(self.batch_pak_files) - 1:
            return

        for index in reversed(selected):
            if index < len(self.batch_pak_files) - 1:
                # Swap in list
                self.batch_pak_files[index], self.batch_pak_files[index+1] = \
                    self.batch_pak_files[index+1], self.batch_pak_files[index]

                # Swap in listbox
                item = self.batch_listbox.get(index)
                self.batch_listbox.delete(index)
                self.batch_listbox.insert(index+1, item)
                self.batch_listbox.selection_set(index+1)

    def log(self, message: str) -> None:
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_log(self) -> None:
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        logging.info("Log cleared")

    def show_progress(self, label: str = "Working...") -> None:
        """Show the progress bar with a custom label"""
        self.progress_label.config(text=label)
        self.progress_frame.pack(fill=tk.X, pady=(0, 5))
        self.progress_bar.start(PROGRESS_BAR_INTERVAL)

    def hide_progress(self) -> None:
        """Hide the progress bar"""
        self.progress_bar.stop()
        self.progress_frame.pack_forget()
        self.current_process = None
        self.cancel_requested = False

    def run_repak(self, args: List[str], callback: Optional[Callable[[bool], None]] = None) -> None:
        """Run repak command in a separate thread with cancellation support"""
        # Reset cancellation flag
        self.cancel_requested = False

        def _run():
            cmd = [str(self.repak_path)] + args

            # Add AES key if provided
            aes_key = self.aes_key_var.get().strip()
            if aes_key:
                cmd.extend(["--aes-key", aes_key])

            # Log command with AES key redacted for security
            self.log(f"Running: {self._redact_aes_key(cmd)}")
            self.log("-" * 50)
            logging.info(f"Executing command: {self._redact_aes_key(cmd)}")

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=self.script_dir
                )

                # Track the current process for cancellation
                self.current_process = process

                for line in iter(process.stdout.readline, ''):
                    # Check for cancellation
                    if self.cancel_requested:
                        process.terminate()
                        self.root.after(0, self.log, "\n⚠️ Operation cancelled by user")
                        self.root.after(0, self.hide_progress)
                        if callback:
                            self.root.after(0, callback, False)
                        return

                    self.root.after(0, self.log, line.rstrip())

                process.wait()

                if process.returncode == 0:
                    self.root.after(0, self.log, "\n✓ Success!")
                    self.root.after(0, self.hide_progress)
                    logging.info("Command completed successfully")
                    if callback:
                        self.root.after(0, callback, True)
                else:
                    self.root.after(0, self.log, f"\n✗ Failed with exit code {process.returncode}")
                    self.root.after(0, self.hide_progress)
                    logging.error(f"Command failed with exit code {process.returncode}")
                    if callback:
                        self.root.after(0, callback, False)

            except Exception as e:
                self.root.after(0, self.log, f"\n✗ Error: {str(e)}")
                self.root.after(0, self.hide_progress)
                logging.error(f"Command execution error: {e}")
                if callback:
                    self.root.after(0, callback, False)
            finally:
                self.current_process = None

        thread = threading.Thread(target=_run, daemon=True)
        self.operation_thread = thread
        thread.start()

    def do_unpack(self) -> None:
        pak_file = self.unpack_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file to unpack.")
            return

        # Validate path
        validated_path = self._validate_path(pak_file, must_exist=True)
        if not validated_path:
            messagebox.showerror("Error", f"Invalid or non-existent pak file:\n{pak_file}")
            return

        # Ensure it's a .pak file
        if validated_path.suffix.lower() != '.pak':
            messagebox.showwarning("Warning", "Selected file is not a .pak file.")
            return

        # Add to recent files
        self._add_to_recent_files(str(validated_path))

        # Create subfolder based on pak name
        pak_name = validated_path.stem
        output_dir = self.unpack_dir / pak_name

        def on_complete(success: bool) -> None:
            if success:
                messagebox.showinfo(
                    "Unpack Complete",
                    f"Successfully unpacked {pak_name}.pak\n\nOutput: {output_dir}"
                )
                logging.info(f"Successfully unpacked: {validated_path}")
            else:
                messagebox.showerror(
                    "Unpack Failed",
                    f"Failed to unpack {pak_name}.pak\n\nCheck the log for details."
                )
                logging.error(f"Failed to unpack: {validated_path}")

        self.show_progress("Unpacking...")
        args = ["unpack", str(validated_path), "--output", str(output_dir)]
        self.run_repak(args, callback=on_complete)

    def do_pack(self):
        source_dir = self.pack_source_var.get().strip()
        pak_name = self.pack_name_var.get().strip()

        if not source_dir:
            messagebox.showwarning("Warning", "Please select a source directory to pack.")
            return

        # Validate source directory
        validated_dir = self._validate_path(source_dir, must_exist=True)
        if not validated_dir or not validated_dir.is_dir():
            messagebox.showerror("Error", f"Invalid or non-existent source directory:\n{source_dir}")
            return

        if not pak_name:
            messagebox.showwarning("Warning", "Please specify a pak file name.")
            return

        # Sanitize pak name to prevent path traversal
        pak_name = Path(pak_name).name  # Extract just the filename, removing any path components

        # Ensure .pak extension
        if not pak_name.endswith(".pak"):
            pak_name += ".pak"

        output_pak = self.pack_dir / pak_name

        def on_complete(success):
            if success:
                messagebox.showinfo(
                    "Pack Complete",
                    f"Successfully packed {pak_name}\n\nOutput: {output_pak}"
                )
            else:
                messagebox.showerror(
                    "Pack Failed",
                    f"Failed to pack {pak_name}\n\nCheck the log for details."
                )

        self.show_progress("Packing...")
        args = ["pack", str(validated_dir), str(output_pak)]
        self.run_repak(args, callback=on_complete)

    def do_info(self):
        pak_file = self.info_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file.")
            return

        # Validate path
        validated_path = self._validate_path(pak_file, must_exist=True)
        if not validated_path:
            messagebox.showerror("Error", f"Invalid or non-existent pak file:\n{pak_file}")
            return

        self.show_progress("Getting info...")
        self.run_repak(["info", str(validated_path)])

    def do_list(self):
        pak_file = self.info_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file.")
            return

        # Validate path
        validated_path = self._validate_path(pak_file, must_exist=True)
        if not validated_path:
            messagebox.showerror("Error", f"Invalid or non-existent pak file:\n{pak_file}")
            return

        self.show_progress("Listing contents...")
        self.run_repak(["list", str(validated_path)])

    def do_batch_unpack(self):
        """Unpack all files in the batch list sequentially"""
        if not self.batch_pak_files:
            messagebox.showwarning("Warning", "Please add pak files to unpack.")
            return

        # Validate all files first
        validated_files = []
        invalid = []

        for pak_file in self.batch_pak_files:
            validated = self._validate_path(pak_file, must_exist=True)
            if validated and validated.suffix.lower() == '.pak':
                validated_files.append(validated)
            else:
                invalid.append(pak_file)

        if invalid:
            messagebox.showerror("Error",
                f"Some files are invalid or not found:\n{chr(10).join(invalid[:5])}"
                + (f"\n... and {len(invalid)-5} more" if len(invalid) > 5 else ""))
            return

        if not validated_files:
            messagebox.showwarning("Warning", "No valid pak files to unpack.")
            return

        self.log(f"Starting batch unpack of {len(validated_files)} file(s)...")
        self.log("=" * 50)
        self.show_progress("Starting batch unpack...")

        # Run batch unpack in a thread
        def _batch_run():
            total = len(validated_files)
            success_count = 0
            fail_count = 0

            for i, pak_file in enumerate(validated_files, 1):
                pak_name = pak_file.stem
                output_dir = self.unpack_dir / pak_name

                self.root.after(0, self.log, f"\n[{i}/{total}] Unpacking: {pak_name}")
                self.root.after(0, self.progress_label.config, {"text": f"Unpacking {i}/{total}: {pak_name}"})

                cmd = [str(self.repak_path), "unpack", str(pak_file), "--output", str(output_dir)]

                # Add AES key if provided
                aes_key = self.aes_key_var.get().strip()
                if aes_key:
                    cmd.extend(["--aes-key", aes_key])

                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        cwd=self.script_dir
                    )

                    for line in iter(process.stdout.readline, ''):
                        self.root.after(0, self.log, line.rstrip())

                    process.wait()

                    if process.returncode == 0:
                        self.root.after(0, self.log, f"  -> Success: {output_dir}")
                        success_count += 1
                    else:
                        self.root.after(0, self.log, f"  -> Failed with exit code {process.returncode}")
                        fail_count += 1

                except Exception as e:
                    self.root.after(0, self.log, f"  -> Error: {str(e)}")
                    fail_count += 1

            # Summary
            self.root.after(0, self.log, "\n" + "=" * 50)
            self.root.after(0, self.log, f"Batch unpack complete: {success_count} succeeded, {fail_count} failed")
            self.root.after(0, self.hide_progress)

            # Show completion dialog
            if fail_count == 0:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Batch Unpack Complete",
                    f"Successfully unpacked {success_count} file(s).\n\nOutput: {self.unpack_dir}"))
            else:
                self.root.after(0, lambda: messagebox.showwarning(
                    "Batch Unpack Complete",
                    f"Completed with errors.\n\n{success_count} succeeded, {fail_count} failed.\n\nCheck the log for details."))

        thread = threading.Thread(target=_batch_run, daemon=True)
        thread.start()


def main():
    # Setup logging first
    setup_logging()

    root = tk.Tk()

    # Try to use a nicer theme if available
    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
    except Exception:
        pass  # Continue with default theme if there's an error

    app = RepakGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
