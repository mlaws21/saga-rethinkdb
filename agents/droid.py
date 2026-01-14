from saga.agent import Agent, get_agent_material
from saga.local_agent import DummyAgent


# Gather required material
agent_workdir = "/home/mlaws21/saga-rethinkdb/saga/user/lola@mail.com:droid/"
agent_material = get_agent_material(agent_workdir)

# Create agent instance 
droid_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=DummyAgent()
)
# Goes online and can accept conversations from other agents
droid_agent.connect("matt@mail.com:myagent", "HELLO WORLD")