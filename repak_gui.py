#!/usr/bin/env python3
"""
Repak GUI - A simple GUI wrapper for repak (Unreal Engine .pak tool)
Designed for STALKER 2 modding
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
import os
from pathlib import Path


class RepakGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Repak GUI - STALKER 2 Pak Tool")
        self.root.geometry("700x500")
        self.root.minsize(600, 400)

        # Find repak binary (same directory as script)
        self.script_dir = Path(__file__).parent.resolve()
        self.repak_path = self.script_dir / "repak"

        # Fixed output directories
        self.unpack_dir = self.script_dir / "unpackedfiles"
        self.pack_dir = self.script_dir / "packedfiles"

        # Create output directories if they don't exist
        self.unpack_dir.mkdir(exist_ok=True)
        self.pack_dir.mkdir(exist_ok=True)

        if not self.repak_path.exists():
            messagebox.showerror("Error", f"repak binary not found at:\n{self.repak_path}")

        # Batch unpack state
        self.batch_pak_files = []

        self.setup_ui()

    def setup_ui(self):
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
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Hide progress bar initially
        self.progress_frame.pack_forget()

        # Output log
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED,
                                                   font=("Monospace", 9))
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
                                         selectmode=tk.EXTENDED, font=("Monospace", 9))
        self.batch_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.batch_listbox.yview)

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

    def update_batch_count(self):
        """Update the file count label"""
        count = len(self.batch_pak_files)
        self.batch_count_var.set(f"{count} file{'s' if count != 1 else ''} selected")

    def log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def show_progress(self, label="Working..."):
        """Show the progress bar with a custom label"""
        self.progress_label.config(text=label)
        self.progress_frame.pack(fill=tk.X, pady=(0, 5))
        self.progress_bar.start(10)

    def hide_progress(self):
        """Hide the progress bar"""
        self.progress_bar.stop()
        self.progress_frame.pack_forget()

    def run_repak(self, args, callback=None):
        """Run repak command in a separate thread"""
        def _run():
            cmd = [str(self.repak_path)] + args

            # Add AES key if provided
            aes_key = self.aes_key_var.get().strip()
            if aes_key:
                cmd.extend(["--aes-key", aes_key])

            self.log(f"Running: {' '.join(cmd)}")
            self.log("-" * 50)

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
                    self.root.after(0, self.log, "\nSuccess!")
                    self.root.after(0, self.hide_progress)
                    if callback:
                        self.root.after(0, callback, True)
                else:
                    self.root.after(0, self.log, f"\nFailed with exit code {process.returncode}")
                    self.root.after(0, self.hide_progress)
                    if callback:
                        self.root.after(0, callback, False)

            except Exception as e:
                self.root.after(0, self.log, f"\nError: {str(e)}")
                self.root.after(0, self.hide_progress)
                if callback:
                    self.root.after(0, callback, False)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

    def do_unpack(self):
        pak_file = self.unpack_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file to unpack.")
            return

        if not os.path.exists(pak_file):
            messagebox.showerror("Error", f"Pak file not found:\n{pak_file}")
            return

        # Create subfolder based on pak name
        pak_name = Path(pak_file).stem
        output_dir = self.unpack_dir / pak_name

        def on_complete(success):
            if success:
                messagebox.showinfo(
                    "Unpack Complete",
                    f"Successfully unpacked {pak_name}.pak\n\nOutput: {output_dir}"
                )
            else:
                messagebox.showerror(
                    "Unpack Failed",
                    f"Failed to unpack {pak_name}.pak\n\nCheck the log for details."
                )

        self.show_progress("Unpacking...")
        args = ["unpack", pak_file, "--output", str(output_dir)]
        self.run_repak(args, callback=on_complete)

    def do_pack(self):
        source_dir = self.pack_source_var.get().strip()
        pak_name = self.pack_name_var.get().strip()

        if not source_dir:
            messagebox.showwarning("Warning", "Please select a source directory to pack.")
            return

        if not os.path.isdir(source_dir):
            messagebox.showerror("Error", f"Source directory not found:\n{source_dir}")
            return

        if not pak_name:
            messagebox.showwarning("Warning", "Please specify a pak file name.")
            return

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
        args = ["pack", source_dir, str(output_pak)]
        self.run_repak(args, callback=on_complete)

    def do_info(self):
        pak_file = self.info_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file.")
            return

        if not os.path.exists(pak_file):
            messagebox.showerror("Error", f"Pak file not found:\n{pak_file}")
            return

        self.show_progress("Getting info...")
        self.run_repak(["info", pak_file])

    def do_list(self):
        pak_file = self.info_pak_var.get().strip()

        if not pak_file:
            messagebox.showwarning("Warning", "Please select a pak file.")
            return

        if not os.path.exists(pak_file):
            messagebox.showerror("Error", f"Pak file not found:\n{pak_file}")
            return

        self.show_progress("Listing contents...")
        self.run_repak(["list", pak_file])

    def do_batch_unpack(self):
        """Unpack all files in the batch list sequentially"""
        if not self.batch_pak_files:
            messagebox.showwarning("Warning", "Please add pak files to unpack.")
            return

        # Verify all files exist first
        missing = [f for f in self.batch_pak_files if not os.path.exists(f)]
        if missing:
            messagebox.showerror("Error", f"Some pak files not found:\n{chr(10).join(missing[:5])}"
                                + (f"\n... and {len(missing)-5} more" if len(missing) > 5 else ""))
            return

        self.log(f"Starting batch unpack of {len(self.batch_pak_files)} file(s)...")
        self.log("=" * 50)

        # Run batch unpack in a thread
        def _batch_run():
            total = len(self.batch_pak_files)
            success_count = 0
            fail_count = 0

            for i, pak_file in enumerate(self.batch_pak_files, 1):
                pak_name = Path(pak_file).stem
                output_dir = self.unpack_dir / pak_name

                self.root.after(0, self.log, f"\n[{i}/{total}] Unpacking: {pak_name}")

                cmd = [str(self.repak_path), "unpack", pak_file, "--output", str(output_dir)]

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
    root = tk.Tk()

    # Try to use a nicer theme if available
    try:
        style = ttk.Style()
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
    except:
        pass

    app = RepakGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
