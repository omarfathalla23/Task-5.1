import { jest } from '@jest/globals';
import bcrypt from 'bcryptjs';
import request from 'supertest';

import app from '../src/app.js';
import { Instructor } from '../src/models/Instructor.js';
import {
  startDb,
  stopDb,
  seed,
  SECRET_FIELDS,
  ADMIN_PASSWORD
} from './helpers/testEnv.js';

jest.setTimeout(120000);

const api = request(app);
const ids = (response) => response.body.instructors.map(({ _id }) => _id).sort();

beforeAll(startDb);
afterAll(stopDb);
beforeEach(seed);

describe('Instructor input and response hardening', () => {
  test('a successful login returns the profile without secret fields', async () => {
    const response = await api.post('/api/instructors/login').send({
      username: 'admin',
      password: ADMIN_PASSWORD
    });

    expect(response.status).toBe(200);
    expect(response.body.instructor).toMatchObject({
      username: 'admin',
      role: 'superadmin'
    });
    for (const field of SECRET_FIELDS) {
      expect(response.body.instructor).not.toHaveProperty(field);
    }
  });

  test('missing credentials and non-string credential values are rejected', async () => {
    const valid = { username: 'admin', password: ADMIN_PASSWORD };
    const invalidValues = [null, [], {}, 42, true, ''];

    for (const field of ['username', 'password']) {
      const missing = { ...valid };
      delete missing[field];
      for (const body of [missing, ...invalidValues.map((value) => ({
        ...valid,
        [field]: value
      }))]) {
        const response = await api.post('/api/instructors/login').send(body);
        expect(response.status).toBe(400);
        expect(response.body.instructor).toBeUndefined();
      }
    }
  });

  test('private fields and injected operators cannot filter public search results', async () => {
    const baseline = await api.get('/api/instructors/search');
    expect(baseline.status).toBe(200);
    expect(baseline.body.count).toBe(4);

    const unsafeQueries = [
      { password: 'definitely-not-the-password' },
      { apiKey: 'definitely-not-the-api-key' },
      { privateEmail: 'root@university.edu' },
      { privatePhone: '+1-555-0000' },
      { $where: 'false' },
      { 'password[$regex]': '^S' },
      { 'role[$ne]': 'instructor' },
      { 'username[$regex]': '^admin' },
      { 'name[0]': 'Portal Administrator' },
      { 'name.last': 'Administrator' }
    ];

    for (const query of unsafeQueries) {
      const response = await api.get('/api/instructors/search').query(query);
      expect(response.status).toBe(200);
      expect(response.body.count).toBe(baseline.body.count);
      expect(ids(response)).toEqual(ids(baseline));
      for (const instructor of response.body.instructors) {
        for (const field of SECRET_FIELDS) {
          expect(instructor).not.toHaveProperty(field);
        }
      }
    }
  });

  test('name searches use literal text even when it contains regex syntax', async () => {
    await Instructor.create({
      name: 'Prof. Regex .* [Tutor]',
      username: 'prof.regex',
      password: 'literal-search-password',
      department: 'CS'
    });

    for (const name of ['.*', '[Tutor]']) {
      const response = await api.get('/api/instructors/search').query({ name });
      expect(response.status).toBe(200);
      expect(response.body.instructors.map((instructor) => instructor.name))
        .toEqual(['Prof. Regex .* [Tutor]']);
    }
  });

  test('partial name search is case-insensitive and public scalar filters work', async () => {
    const partial = await api.get('/api/instructors/search').query({ name: 'sMiTh' });
    expect(partial.status).toBe(200);
    expect(partial.body.instructors.map((instructor) => instructor.name))
      .toEqual(['Prof. Alice Smith']);

    const exact = await api.get('/api/instructors/search').query({
      username: 'admin',
      department: 'IT',
      role: 'superadmin'
    });
    expect(exact.status).toBe(200);
    expect(exact.body.count).toBe(1);
    expect(exact.body.instructors[0].name).toBe('Portal Administrator');
  });

  test('passwords verify with bcrypt and only rehash when changed', async () => {
    const admin = await Instructor.findOne({ username: 'admin' }).select('+password');
    const initialHash = admin.password;
    expect(await bcrypt.compare(ADMIN_PASSWORD, initialHash)).toBe(true);

    admin.name = 'Updated Administrator';
    await admin.save();
    const unchanged = await Instructor.findById(admin._id).select('+password');
    expect(unchanged.password).toBe(initialHash);

    const replacement = 'New-admin-password!';
    unchanged.password = replacement;
    await unchanged.save();
    const updated = await Instructor.findById(admin._id).select('+password');
    expect(updated.password).not.toBe(initialHash);
    expect(updated.password).not.toBe(replacement);
    expect(await bcrypt.compare(replacement, updated.password)).toBe(true);
    expect(await bcrypt.compare(ADMIN_PASSWORD, updated.password)).toBe(false);

    const response = await api.post('/api/instructors/login').send({
      username: 'admin',
      password: replacement
    });
    expect(response.status).toBe(200);
  });
});
