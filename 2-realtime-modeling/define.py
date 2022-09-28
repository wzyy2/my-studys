#!/usr/bin/env python3

import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, currentdir) 

import bdsim

sim = bdsim.BDSim(debug='g', animation=True, graphics=True)  # create simulator
bd = sim.blockdiagram()  # create an empty block diagram
sim.blocks()

print(sim.options)
sim.set_options(animation=True)

# define the blocks
demand = bd.STEP(T=1, name='demand')
sum = bd.SUM('+-')
gain = bd.GAIN(10)
plant = bd.LTI_SISO(0.5, [2, 1], name='plant')
scope = bd.SCOPE(styles=['k', 'r--']) #, movie='eg1.mp4')

# connect the blocks
bd.connect(demand, sum[0], scope[1])
bd.connect(plant, sum[1])
bd.connect(sum, gain)
bd.connect(gain, plant)
bd.connect(plant, scope[0])

bd.report()

bd.compile()   # check the diagram
bd.report_summary()    # list all blocks and wires
sim.showgraph(bd)

# out = sim.run(bd)  # simulate for 5s
# out = sim.run(bd, 5 watch=[plant,demand])  # simulate for 5s
# print(out)
