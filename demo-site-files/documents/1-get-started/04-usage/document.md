# Usage

## Creating Content

1. Log in with admin credentials
2. Use the "New" button to create a new document
3. Write content using Markdown syntax
4. Save your document

## Organizing Content

LeoMoon Wiki-Go allows you to organize content in a hierarchical structure:

1. Create directories to group related documents
2. Use the move/rename feature to reorganize content when in edit mode
3. Navigate through your content using the sidebar or breadcrumbs

## Using Kanban Boards

LeoMoon Wiki-Go supports interactive Kanban boards for project management and task tracking. You can transform any document into a visual project board.

### Creating a Kanban Board

There are two ways to create a kanban board:

#### Method 1: Create New Kanban Document
1. Click the "New" button to create a new document
2. In the document creation dialog, select "Kanban Board" as the document type
3. Enter your document name and location
4. The document will be automatically created with kanban layout and basic structure

#### Method 2: Convert Existing Document
1. Open an existing document and enter edit mode
2. Position your cursor where you want the kanban board to be inserted
3. Click the "Add Kanban" button in the editor toolbar
4. The kanban frontmatter and basic board structure will be added at the cursor position
5. Save the document to apply the kanban layout

#### Method 3: Manual Setup
1. Create a new document or edit an existing one
2. Add the following frontmatter at the top of your document:
   ```yaml
   ---
   layout: kanban
   ---
   ```
3. Structure your content using the following format:
   ```
   # Your Project Title

   #### Project Board Name (optional)

   ##### To Do
   - [ ] Task 1
   - [ ] Task 2 with **formatting**
   - [ ] Task with [links](https://example.com)

   ##### In Progress
   - [ ] Current task
   - [ ] Another active task
     - [ ] Sub-task 1
     - [ ] Sub-task 2

   ##### Done
   - [x] Completed task
   - [x] Another finished task
   ```

### Working with Kanban Boards

- **Drag and Drop**: Click and drag tasks between columns to update their status
- **Edit Tasks**: Click on any task to edit its content inline
- **Add Tasks**: Use the "+" button in column headers to add new tasks
- **Nested Tasks**: Indent tasks with spaces to create sub-tasks
- **Markdown Support**: Tasks support full markdown formatting (bold, italic, links, code, etc.)
- **Multiple Boards**: Add multiple kanban boards in one document by repeating the H4/H5 structure

### Managing Columns

- **Rename Columns**: Click the pencil icon in column headers to rename
- **Add Columns**: Create new columns by adding H5 headers in your markdown or using the interface
- **Delete Columns**: Use the trash icon to remove empty columns
- **Duplicate Names**: Column names can be duplicated without data loss

### Best Practices

- Use descriptive column names that reflect your workflow (e.g., "Backlog", "In Review", "Testing")
- Keep task descriptions concise but informative
- Use sub-tasks for breaking down complex work
- Regularly review and update task status by moving them between columns

## Attaching Files

You can attach files to any document:

1. Navigate to the document and enter edit mode
2. Click the "Attachments"
3. Upload files using the upload button
4. Use "Files" tab to insert links to files in your document

## Using Comments

The commenting system allows users to provide feedback and engage in discussions:

1. Navigate to any document
2. Scroll to the comments section at the bottom
3. Authenticated users can add comments using Markdown syntax
4. Administrators can delete any comments
5. Comments can be disabled system-wide through the admin settings panel

### Importing from Notion

If you are migrating from Notion, a community-provided Python script is available to help import your Notion markdown export directly into Wiki-Go's document tree. It automatically converts page hierarchies and handles file attachments.

For detailed instructions, see the [Notion Import Tool Documentation](https://github.com/leomoon-studios/wiki-go/tree/master/tools/notion-import).
