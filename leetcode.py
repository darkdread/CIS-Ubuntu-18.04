from typing import List

class Solution:
    
    def isRectangleCover(self, rectangles: List[List[int]]) -> bool:
        coveredGrids = []
        btmLowestPoint = [100, 100]
        topHighestPoint = [0, 0]
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
            
            xlen = tr[0] - bl[0]
            ylen = tr[1] - bl[1]
            
            if (xlen <= 0 or ylen <= 0):
                return False
            
            for y in range(ylen):
                for x in range(xlen):
                    grid = [bl[0] + x, bl[1] + y, bl[0] + x + 1, bl[1] + y + 1]
                    coveredGrids.append(grid)

        print(coveredGrids)
        print(len(coveredGrids))
        print(btmLowestPoint, topHighestPoint)
        
        for y in range(topHighestPoint[1] - btmLowestPoint[1]):
            for x in range(topHighestPoint[0] - btmLowestPoint[0]):
                gridExist = False
                for grid in coveredGrids:
                    if (grid[0] - btmLowestPoint[0] == x and grid[1] - btmLowestPoint[1] == y and grid[2] - btmLowestPoint[0] == x + 1 and grid[3] - btmLowestPoint[1] == y + 1):
                        coveredGrids.remove(grid)
                        gridExist = True
                        break

                if not (gridExist):
                    return False

        print(coveredGrids)
        
        if (len(coveredGrids) == 0):
            return True
            
        return False


meme = Solution()

rect = []

meme.isRectangleCover(rect)
