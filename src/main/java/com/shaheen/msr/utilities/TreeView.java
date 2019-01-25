package com.shaheen.msr.utilities;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class TreeView {

    public void printDirectoryTree(File folder) {
        if (!folder.isDirectory()) {
            throw new IllegalArgumentException("folder is not a Directory");
        }
        int indent = 0;
        StringBuilder sb = new StringBuilder();
        List<Boolean> hierarchyTree = new ArrayList<>();
        renderFolder(folder, indent, sb, false, hierarchyTree);
        System.out.println(sb.toString());
//        return sb.toString();
    }

    private static StringBuilder renderFolder(File folder, int level, StringBuilder sb, boolean isLast, List<Boolean> hierarchyTree) {
        indent(sb, level, isLast, hierarchyTree).append(folder.getName()).append("\n");
        //This filters Only folders
//        File[] objects = folder.listFiles(new FilenameFilter() {
//            @Override
//            public boolean accept(File current, String name) {
//                return new File(current, name).isDirectory();
//            }
//        });
        if (folder.isDirectory()) { //For Files
            File[] objects = folder.listFiles();
            for (int i = 0; i < objects.length; i++) {
                boolean last = ((i + 1) == objects.length);
                // this means if the current folder will still need to print subfolders at this level, if yes, then we need to continue print |
                hierarchyTree.add(i != objects.length - 1);
                renderFolder(objects[i], level + 1, sb, last, hierarchyTree);
                // pop the last value as we return from a lower level to a higher level
                hierarchyTree.remove(hierarchyTree.size() - 1);
            }
        }//For files
        return sb;
    }

    private static StringBuilder indent(StringBuilder sb, int level, boolean isLast, List<Boolean> hierarchyTree) {
        // System.out.println("SB: " + sb.toString());
        String indentContent = "\u2502   ";
        for (int i = 0; i < hierarchyTree.size() - 1; ++i) {
            // determines if we need to print | at this level to show the tree structure
            // i.e. if this folder has a sibling folder that is going to be printed later
            if (hierarchyTree.get(i)) {
                sb.append(indentContent);
            } else {
                sb.append("    "); // otherwise print empty space
            }
        }
        if (level > 0) {
            sb.append(isLast ? "\u2514\u2500\u2500" : "\u251c\u2500\u2500");
        }
        return sb;
    }
}