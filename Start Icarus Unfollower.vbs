' Plug-and-play launch for Icarus Un-follower -- double-click me. No console.
' Requires Python (python.org). For a no-Python build, run build_exe.bat once
' to produce dist\IcarusUnfollower.exe instead.
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
Set sh = CreateObject("WScript.Shell")
sh.CurrentDirectory = here
On Error Resume Next
sh.Run "pythonw """ & here & "\launcher.py""", 0, False
If Err.Number <> 0 Then
    Err.Clear
    sh.Run "python """ & here & "\launcher.py""", 0, False
End If
If Err.Number <> 0 Then
    MsgBox "Could not find Python. Install it from python.org (tick 'Add to PATH'), then double-click me again.", 16, "Icarus Un-follower"
End If
