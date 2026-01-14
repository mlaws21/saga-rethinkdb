from saga.agent import Agent, get_agent_material
from saga.local_agent import DummyAgent


# Gather required material
agent_workdir = "/home/mlaws21/saga-rethinkdb/saga/user/matt@mail.com:sender/"
agent_material = get_agent_material(agent_workdir)

# Create agent instance 
sender_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=DummyAgent()
)
# Goes online and can accept conversations from other agents
sender_agent.connect("matt@mail.com:recver3", "HELLO WORLD")

# from saga.agent import Agent, get_agent_material
# from saga.local_agent import DummyAgent


# # Gather required material
# agent_workdir = "/home/mlaws21/saga/saga/user/test@test.com:a1/"
# agent_material = get_agent_material(agent_workdir)

# # Create agent instance 
# droid_agent = Agent(
#     workdir=agent_workdir,
#     material=agent_material,
#     local_agent=DummyAgent()
# )
# # Goes online and can accept conversations from other agents
# droid_agent.connect("test@test.com:a3", "HELLO WORLD")