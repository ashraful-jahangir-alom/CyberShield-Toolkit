$root = "C:\CyberChieldToolKit"
$extensions = @('.py', '.html', '.css', '.js', '.md', '.txt', '.env')
Get-ChildItem -Path $root -Recurse -File |
  Where-Object {
    $ext = $_.Extension
    $ext -in $extensions -and
    $_.FullName -notmatch 'site-packages|dist-info|__pycache__|\.git|\.venv|proj_files\.txt|tree\.txt'
  } |
  Select-Object -ExpandProperty FullName
