from random import randint
from rich import print

def get_user_agent():
    with open('utils/user-agents.txt') as agents_file:
        user_agents = agents_file.readlines()
        user_agent = user_agents[randint(0, len(user_agents) -1)]

        chars = "b'"
        user_agent = user_agent.replace(chars, "")
        user_agent = user_agent.replace("'", "")
        user_agent = user_agent.encode('utf-8')

        return str(user_agent)

get_user_agent()