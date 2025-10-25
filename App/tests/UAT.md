# User Acceptance Tests (UAT)

## 1. Employer Functions

### Test Case: Create Internship Position
**Steps:**
1. Login as employer
2. Navigate to position creation
3. Enter position details:
   - Title: "Junior Developer"
   - Description: "Entry level position"
   - Requirements: "Python knowledge"
4. Submit position

**Success Criteria:**
- Position appears in employer's positions list
- Position is searchable by students
- All entered details are displayed correctly

### Test Case: Review Shortlisted Candidates
**Steps:**
1. Login as employer
2. Navigate to "View Shortlisted Students"
3. Select a position

**Success Criteria:**
- Can view all shortlisted candidates
- List displays correct student details

### Test Case: Accept or Reject Student
**Steps:**
1. Navigate to "View Shortlisted Students"
2. Select a student
3. Click Accept or Reject
   
 **Success Criteria:**  
- System updates student’s application status correctly

## 2.1 Staff Functions

### Test Case: Select Internship Position
**Steps:**
1.Navigate to "Internship Position and Shortlist"
2.Open the internship position dropdown
3.Select the desired position

**Success Criteria:**
- Details of the selected position (title, employer, requirements) are displayed correctly

### Test Case: Search for Students
**Steps:**
1.Open "Add Student to Shortlist"
2.Enter search criteria (name, GPA, program, skills)
3.Click Search

**Success Criteria:**
- List of students matching the criteria appears
- Student records show essential details (name, program, GPA, application files)

### Test Case: Shortlist Students
**Steps:**
1. Login as staff
2. Navigate to "Add Student to Shortlist"
3. Search for eligible students
4. Add students to shortlist

**Success Criteria:**
- Students are successfully added to shortlist
- Shortlist is visible to employer
- Multiple students can be added

## 3. Student Functions

### Test Case: Create Application
**Steps:**
1. Click on "My documents" or navigate to "My Application Documents"
3. Fill out required fields
4. Submit application

**Success Criteria:**
- Application is saved as "Submitted to Staff" / "Pending Staff Review"

### Test Case: View Shortlisted Positions
**Steps:**
1. Login as student
2. Navigate to "My Shortlisted Positions"
3. Check status of applications

**Success Criteria:**
- Can see all positions they're shortlisted for
- Status (pending/accepted/rejected) is clearly displayed
- Can view position details

### Test Case: Accept
**Steps:**
1. Navigate to "Employer Response"
2. Click Accept
3. Confirm action

**Success Criteria:**
- System updates offer to accepted

### Test Case: Reject
**Steps:**
1. Navigate to "Employer Response"
2. Click Reject
3. Confirm action

**Success Criteria:**
- System updates offer to rejected

jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj
## 1. Unauthorized Access

### Test Case: Users who are not logged in
**Steps:**
1. Attempt to access "My Shortlisted Positions" 

**Success Criteria:**
- System redirects to login or displays an error message


