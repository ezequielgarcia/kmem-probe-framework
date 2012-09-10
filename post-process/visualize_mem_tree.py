# 
# Color handling based on gnome's baobab. See baobab-chart.c, Copyright (C) Igalia
#
# Of course, there are far more pythonic ways to handle
# colors... but right now: let's make this work!
#

import math
import pylab
from matplotlib.colors import colorConverter
from matplotlib.patches import Wedge
from matplotlib.collections import PatchCollection

tango_colors = ['#ef2929',
		'#ad7fa8',
		'#729fcf',
		'#8ae234',
		'#e9b96e',
		'#fcaf3e',]

class Section:
	def __init__(self, node, size, total_size, total_angle, start_angle):
		self.node = node
		self.size = size
		self.start_angle = start_angle
		self.angle = size * total_angle / total_size

def ring_color(start_angle, level):

        # f:      [1 - 0.26]
        # rel:    [0 - 198]
        # icolor: [0 - 5]
        f = 1 - (((level-1) * 0.3) / 8)
        rel = start_angle / 180. * 99

        icolor = int(rel / (100./3))
        next_icolor = (icolor + 1) % 6

        # Interpolate (?)
        color = colorConverter.to_rgb(tango_colors[icolor])
        next_color = colorConverter.to_rgb(tango_colors[next_icolor])
        p = (rel - icolor * 100./3) / (100./3)

        # color = intensity * (color - percentage * (color - next_color))
        color = [f * (c - p * (c - n)) for c, n in zip(color, next_color)]

        return color

def create_rings(tree, level=1, level_angle=360, start_angle=0, rings=[],
		 radius=0.1, center=(1.0,1.0), size_attr="static"):

	child_size = 0
	max_size = getattr(tree.size(), size_attr)

	if len(tree.childs) == 0:
		return rings

	if max_size == 0:
		for name, node in tree.childs.items():
			max_size += getattr(node.size(), size_attr)
	if max_size == 0:
		return rings

	s_angle = start_angle
	sections = {}
	for name, node in tree.childs.items():

		size = getattr(node.size(), size_attr)
		s = Section(node, size, max_size, level_angle, s_angle)
		sections[name] = s

		create_rings(node, level+1, s.angle, s_angle, rings, radius, center, size_attr)
		s_angle += s.angle
		child_size += size

	# Just a check
	if child_size > max_size:
		print "[{}] Ooops, child size is greater than max size".format(name)

	for name, section in sections.items():
		
		# Create tuple: (wedge, name)
		tup = (	Wedge(center, 
			level * radius, 
			section.start_angle, 
			section.start_angle + section.angle, 
			width=radius,
			facecolor=ring_color(section.start_angle, level)),
			name)

		rings.append(tup)

	return rings

def visualize_mem_tree(tree, attr="static"):

	RING_MIN_WIDTH = 1
	TEXT_MIN_WIDTH = 1

	print "[Visualize] Creating rings"
	rings = create_rings(tree, level=2, size_attr=attr)

	print "[Visualize] Plotting", len(rings)
	fig = pylab.figure()
	ax = fig.add_subplot(111)

	for p in rings:
		wedge = p[0]

		# Skip if too small
		if (wedge.theta2 - wedge.theta1) < RING_MIN_WIDTH:
			continue

		# Add wedge
		ax.add_patch(wedge)

		# Skip text if too small
		if (wedge.theta2 - wedge.theta1) < TEXT_MIN_WIDTH:
			continue

		text = p[1]
		theta = math.radians((wedge.theta1 + wedge.theta2) / 2.)
		x0 = wedge.center[0] + (wedge.r - wedge.width/2.) * math.cos(theta)
		y0 = wedge.center[1] + (wedge.r - wedge.width/2.) * math.sin(theta)
		x = wedge.center[0] + (wedge.r - wedge.width/2. + 0.1) * math.cos(theta)
		y = wedge.center[1] + (wedge.r - wedge.width/2. + 0.1) * math.sin(theta)

		ax.plot(x0,y0, ".", color="black")
		ax.annotate(text, 
			    size=15,
			    bbox=dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8),
			    xy=(x0, y0), xycoords='data',
			    xytext=(x, y), textcoords='data',
			    arrowprops=dict(arrowstyle="-", 
			    		    connectionstyle="angle3, angleA=0, angleB=90"),)

	pylab.show()
