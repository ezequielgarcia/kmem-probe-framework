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

CENTER_X = 1.0
CENTER_Y = 1.0
WIDTH = 0.2
tango_colors = ['#ef2929',
        '#ad7fa8',
        '#729fcf',
        '#8ae234',
        '#e9b96e',
        '#fcaf3e',]


def human_bytes(bytes, precision=1):
    """Return a humanized string representation of a number of bytes.

    Assumes `from __future__ import division`.

    >>> humanize_bytes(1)
    '1 byte'
    >>> humanize_bytes(1024)
    '1.0 kB'
    >>> humanize_bytes(1024*123)
    '123.0 kB'
    >>> humanize_bytes(1024*12342)
    '12.1 MB'
    >>> humanize_bytes(1024*12342,2)
    '12.05 MB'
    >>> humanize_bytes(1024*1234,2)
    '1.21 MB'
    >>> humanize_bytes(1024*1234*1111,2)
    '1.31 GB'
    >>> humanize_bytes(1024*1234*1111,1)
    '1.3 GB'
    """
    abbrevs = (
        (1<<50L, 'PB'),
        (1<<40L, 'TB'),
        (1<<30L, 'GB'),
        (1<<20L, 'MB'),
        (1<<10L, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    return '{0:.{1}f} {2}'.format(bytes / factor, precision, suffix)


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

        if level == 1:
            return colorConverter.to_rgb('#808080')

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

def create_child_rings(tree, level=2, level_angle=360, start_angle=0, rings=[],
         radius=WIDTH, center=(CENTER_X, CENTER_Y), size_attr="static"):

    child_size = 0
    max_size = getattr(tree.size(), size_attr)()

    if len(tree.childs) == 0:
        return rings

    if max_size == 0:
        for name, node in tree.childs.items():
            max_size += getattr(node.size(), size_attr)()
    if max_size == 0:
        return rings

    s_angle = start_angle
    sections = {}

    # Create child wedges
    for name, node in tree.childs.items():

        size = getattr(node.size(), size_attr)()
        s = Section(node, size, max_size, level_angle, s_angle)
        sections[name] = s

        create_child_rings(node, level+1, s.angle, s_angle, rings, radius, center, size_attr)
        s_angle += s.angle
        child_size += size

    # Just a check
    if child_size > max_size:
        print "[{}] Ooops, child size is greater than max size".format(name)

    for name, section in sections.items():

        # Create tuple: (wedge, name)
        name = "{} {}".format(name, human_bytes(section.size))
        tup = ( Wedge(center,
            level * radius,
            section.start_angle,
            section.start_angle + section.angle,
            width=radius,
            facecolor=ring_color(section.start_angle, level)),
            name)

        rings.append(tup)

    return rings

def visualize_mem_tree(tree, size_attr="static", filename="ringchart"):

    RING_MIN_WIDTH = 1
    TEXT_MIN_WIDTH = 5

    rings = create_child_rings(tree, size_attr=size_attr)

    fig = pylab.figure()
    ax = fig.add_subplot(111)
    annotations = []
    labels = []

    text = "{} {}".format(tree.name,
                          human_bytes(getattr(tree.size(), size_attr)()))
    ann = ax.annotate(text,
                      size=12,
                      bbox=dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8),
                      xy=(CENTER_X, CENTER_Y), xycoords='data',
                      xytext=(CENTER_X, CENTER_Y), textcoords='data')
    annotations.append(ann)

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

        theta = math.radians((wedge.theta1 + wedge.theta2) / 2.)
        x0 = wedge.center[0] + (wedge.r - wedge.width / 2.) * math.cos(theta)
        y0 = wedge.center[1] + (wedge.r - wedge.width / 2.) * math.sin(theta)
        x = wedge.center[0] + (0.1 + wedge.r * 1.5 - wedge.width / 2.) * math.cos(theta)
        y = wedge.center[1] + (0.1 + wedge.r * 1.5 - wedge.width / 2.) * math.sin(theta)

        ax.plot(x0, y0, ".", color="black")

        text = p[1]
        ann = ax.annotate(text,
                    size=12,
                    bbox=dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8),
                    xy=(x0, y0), xycoords='data',
                    xytext=(x, y), textcoords='data',
                    arrowprops=dict(arrowstyle="-", connectionstyle="angle3, angleA=0, angleB=90"),)
        annotations.append(ann)

    (alloc, req) = tree.db.get_bytes()
    #txt = "Current {}\nWasted {}\nYou're wasting {}%\n".format(
    #                human_bytes(alloc),
    #                human_bytes(alloc - req),
    #                human_bytes((alloc - req) * 100.0 / alloc))
    #
    #ax.annotate(txt,
    #            xy=(-0.05, 0.8), xycoords='axes fraction',
    #            fontsize=15, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.9))

    pylab.axis('off')
    pylab.savefig("{}.png".format(filename),
                  bbox_extra_artists=annotations,
                  bbox_inches='tight', dpi=300)
