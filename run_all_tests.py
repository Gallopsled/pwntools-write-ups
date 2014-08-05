from pwn import *

for path, dirs, files in os.walk('.'):
    if '.git' in path:
        continue

    if not dirs:
        for f in files:
            if f.startswith('harness'):
                h = log.waitfor('Running harness for ' + path)
                data = process("./" + f, cwd = path, log_level = 0).recvall().strip() 
                if data == 'ok':
                    h.success()
                else:
                    h.failure('Got output:\n' + data)
                break
        else:
            log.warning(path + ' has no harness')
