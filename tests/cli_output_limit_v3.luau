local chunk = string.rep("x", 60 * 1024)
for _ = 1, 100 do
    print(chunk)
end
error("output limit did not stop the script")
