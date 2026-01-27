from saga.agent import Agent, get_agent_material
from saga.local_agent import DummyAgent


# Gather required material
agent_workdir = "/home/mlaws21/saga-rethinkdb/saga/user/hacker@mail.com:hacked/"
agent_material = get_agent_material(agent_workdir)

# Create agent instance 
recver_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=DummyAgent()
)

# Attempts to start a new conversation with Alice's email agent.
recver_agent.listen()

# from saga.agent import Agent, get_agent_material
# from saga.local_agent import DummyAgent


# # Gather required material
# agent_workdir = "/home/mlaws21/saga/saga/user/test@test.com:a3/"
# agent_material = get_agent_material(agent_workdir)

# # Create agent instance 
# myagent_agent = Agent(
#     workdir=agent_workdir,
#     material=agent_material,
#     local_agent=DummyAgent()
# )

# # Attempts to start a new conversation with Alice's email agent.
# myagent_agent.listen()