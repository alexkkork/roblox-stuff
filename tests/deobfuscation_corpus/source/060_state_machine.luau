-- corpus: state_machine; variant: 3
local state, steps = "start", 0
while state ~= "done" do
  steps += 1
  if state == "start" then state = "work" elseif steps >= 2 then state = "done" end
end
print(state, steps)
