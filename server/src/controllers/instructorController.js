import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

const publicFields = 'name department role';
const loginSchema = Joi.object({
  username: Joi.string().max(100).required(),
  password: Joi.string().max(1024).required()
}).required();
const searchSchema = Joi.object({
  name: Joi.string().trim().max(100).allow(''),
  username: Joi.string().trim().max(100).allow(''),
  department: Joi.string().trim().max(100).allow(''),
  role: Joi.string().trim().max(100).allow('')
});

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body, { convert: false });
    if (error) {
      return res.status(400).json({ message: 'Provide a valid username and password as strings' });
    }

    const instructor = await Instructor.findOne({ username: value.username })
      .select('name username department role +password');
    if (!instructor || !(await instructor.comparePassword(value.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select(publicFields)
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // Ignore unknown fields and structured input; only public string filters
    // are eligible for validation. Client operators never reach MongoDB.
    const input = {};
    for (const field of ['name', 'username', 'department', 'role']) {
      if (typeof req.query[field] === 'string') input[field] = req.query[field];
    }
    const { value, error } = searchSchema.validate(input);
    if (error) return res.status(400).json({ message: 'Invalid search filters' });

    const filter = {};
    for (const [field, term] of Object.entries(value)) {
      if (!term) continue;
      // The UI supports partial names. Escape regex syntax so it is literal.
      filter[field] = field === 'name'
        ? new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
        : term;
    }

    const instructors = await Instructor.find(filter)
      .select(publicFields)
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
