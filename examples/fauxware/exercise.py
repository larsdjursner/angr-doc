
import angr

def symbolicExecution():
    p = angr.Project('fauxware', auto_load_libs=False)
    state = p.factory.entry_state()
    sm = p.factory.simulation_manager(state)
    sm.explore(find=lambda x: b'Welcome to the admin console, trusted user!\n' in x.posix.dumps(1))
    res = sm.found[0]

    return res.posix.dumps(0)

if __name__ == "__main__":
    print(symbolicExecution())