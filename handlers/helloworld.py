"""
This is an example of a custom webhook handler
This "handle" function is dynamically loaded and called as the result
of an incoming custom webhook

A custom handler is only REQUIRED to have a function "handle"
handle() should take 2 parameters:
    webhookObj: The dictionary obj from configuration file
    data: the query, post, and json params from the incoming webhook request
    
    
The Hello World example only prints a simple message
A real handler would take the data and perform some actions on it
"""

def handle(webhookObj, data):
    name = webhookObj["name"]
    print(f"Hello World! - Handling webhook [{name}]")