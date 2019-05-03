import math

class Solution:
    
    def isRectangleCover(self, rectangles: List[List[int]]) -> bool:
        coveredGrids = []
        btmLowestPoint = [math.inf, math.inf]
        topHighestPoint = [-math.inf, -math.inf]
        drawnx = []
        drawny = []
        xlen = 0
        ylen = 0
        areaRect = 0
        totalAreaRect = 0

        for rectangle in rectangles:
            bl = rectangle[:2]
            tr = rectangle[2:]
            # print(bl, tr)
            if (bl[0] < btmLowestPoint[0]):
                if (bl[1] >= btmLowestPoint[1]):
                    btmLowestPoint = [bl[0], btmLowestPoint[1]]
                else:
                    btmLowestPoint = [bl[0], bl[0]]

            if (bl[1] < btmLowestPoint[1]):
                if (bl[0] >= btmLowestPoint[1]):
                    btmLowestPoint = [btmLowestPoint[0], bl[1]]
                else:
                    btmLowestPoint = [bl[1], bl[1]]
                    
            if (tr[0] > topHighestPoint[0]):
                if (tr[1] >= topHighestPoint[1]):
                    topHighestPoint = [tr[0], tr[1]]
                else:
                    topHighestPoint = [tr[0], topHighestPoint[1]]
                    
            if (tr[1] > topHighestPoint[1]):
                if (tr[0] >= topHighestPoint[0]):
                    topHighestPoint = [tr[0], tr[1]]
                else:
                    topHighestPoint = [topHighestPoint[0], tr[1]]

        areaRect = (topHighestPoint[0] - btmLowestPoint[0]) * (topHighestPoint[1] - btmLowestPoint[1])

        for rectangle in rectangles:
            bl = rectangle[:2]
            tr = rectangle[2:]
#             4+2+2+2+1+2+1+4+2+2+1+1
            totalAreaRect += (tr[1] - bl[1]) * (tr[0] - bl[0])
#             Drawing horizontally
            if (bl[1] == btmLowestPoint[1]):
                for x in drawnx:
                    if (bl[0] < x[1] and bl[0] >= x[0]):
                        return False
                drawnx.append([bl[0],tr[0]])
                xlen += tr[0] - bl[0]

#             Drawing vertically
            if (bl[0] == btmLowestPoint[0]):
                for y in drawny:
                    if (bl[1] < y[1] and bl[1] >= y[0]):
                        return False
                drawny.append([bl[1],tr[1]])
                ylen += tr[1] - bl[1]
    
        print(btmLowestPoint, topHighestPoint)
        print(xlen, ylen)
        print(drawnx, ",", drawny)
        print(areaRect)
        print(totalAreaRect)
        
        if ((areaRect != totalAreaRect) or (xlen != topHighestPoint[0] - btmLowestPoint[0]) or (ylen != topHighestPoint[1] - btmLowestPoint[1])):
            return False

        return True
