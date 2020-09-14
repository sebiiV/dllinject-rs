# dllinject-rs

Probably going to be incorporate into some function hooking shenanigans

``CARGO_LOG=info cargo run``

![alt text](https://github.com/sebiiV/dllinject-rs/blob/master/screenshots/1.png?raw=true)

Variables are inherited from the injected process.

	The directory from which the application loaded.he current directory.
	The system directory. Use the GetSystemDirectory function to get the path of this directory.
	The 16-bit system directory. 
	There is no function that obtains the path of this directory, but it is searched.
	The Windows directory. 
	Use the GetWindowsDirectory function to get the path of this directory.he directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the App Paths registry key. The App Paths key is not used when computing the DLL search path.
